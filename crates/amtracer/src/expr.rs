use amtracer_abi::{
    CapturePlan, KIND_BYTES, KIND_SCALAR, KIND_STRING, MAX_CAPTURE_BYTES, MAX_READS, ReadStep,
};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct Expression {
    pub text: String,
    tree: Node,
    pub format: Format,
    kind: u32,
    bytes: u32,
}
#[derive(Clone, Debug)]
enum Node {
    Register(u32),
    Constant(u64),
    Add(Box<Node>, Box<Node>),
    Sub(Box<Node>, Box<Node>),
    Read(Box<Node>),
}
#[derive(Clone, Copy, Debug)]
pub struct Format {
    width: u32,
    signed: bool,
}

impl FromStr for Expression {
    type Err = anyhow::Error;
    fn from_str(text: &str) -> Result<Self> {
        ensure!(
            !text.is_empty() && text.len() <= 1024,
            "expression must contain 1..1024 bytes"
        );
        let (body, format) = if let Some((body, ty)) = text.rsplit_once(':') {
            let (signed, width) = match ty.trim() {
                "u8" => (false, 1),
                "u16" => (false, 2),
                "u32" => (false, 4),
                "u64" => (false, 8),
                "i8" => (true, 1),
                "i16" => (true, 2),
                "i32" => (true, 4),
                "i64" => (true, 8),
                _ => bail!("unknown scalar type {ty}"),
            };
            (body, Format { width, signed })
        } else {
            (
                text,
                Format {
                    width: 8,
                    signed: false,
                },
            )
        };
        let mut parser = Parser {
            input: body.as_bytes(),
            position: 0,
            depth: 0,
        };
        parser.space();
        let kind = if parser.consume_word(b"bytes") {
            KIND_BYTES
        } else if parser.consume_word(b"cstr") {
            KIND_STRING
        } else {
            KIND_SCALAR
        };
        let (tree, bytes) = if kind == KIND_SCALAR {
            (parser.sum()?, 0)
        } else {
            ensure!(
                !text.contains(':'),
                "scalar type suffix is invalid for bytes/cstr"
            );
            parser.expect(b'(')?;
            let tree = parser.sum()?;
            parser.expect(b',')?;
            let Node::Constant(length) = parser.primary()? else {
                bail!("capture length must be a constant")
            };
            ensure!(
                length != 0 && length <= MAX_CAPTURE_BYTES as u64,
                "capture length must be 1..{MAX_CAPTURE_BYTES}"
            );
            parser.expect(b')')?;
            (tree, u32::try_from(length)?)
        };
        parser.space();
        ensure!(
            parser.position == parser.input.len(),
            "unexpected token at byte {}",
            parser.position
        );
        let expression = Self {
            text: text.to_owned(),
            tree,
            format,
            kind,
            bytes,
        };
        expression.compile()?;
        Ok(expression)
    }
}

impl Expression {
    pub fn compile(&self) -> Result<CapturePlan> {
        let mut plan = CapturePlan {
            kind: self.kind,
            byte_length: self.bytes,
            ..Default::default()
        };
        self.tree.compile(&mut plan)?;
        if self.kind == KIND_SCALAR && plan.read_count != 0 {
            plan.reads[plan.read_count as usize - 1].width = self.format.width;
        }
        Ok(plan)
    }

    pub fn format_scalar(&self, value: u64) -> Value {
        let bits = self.format.width * 8;
        let masked = if bits == 64 {
            value
        } else {
            value & ((1_u64 << bits) - 1)
        };
        if self.format.signed {
            // Two's-complement reinterpretation, not a potentially lossy input conversion.
            let signed = i64::from_ne_bytes((masked << (64 - bits)).to_ne_bytes()) >> (64 - bits);
            json!({"decimal":signed,"hex":format!("{masked:#x}")})
        } else {
            json!({"decimal":masked,"hex":format!("{masked:#x}")})
        }
    }

    pub fn kind(&self) -> u32 {
        self.kind
    }
}

impl Node {
    fn constant(&self) -> Result<Option<i128>> {
        Ok(match self {
            Self::Constant(value) => Some(i128::from(*value)),
            Self::Add(a, b) => match (a.constant()?, b.constant()?) {
                (Some(a), Some(b)) => Some(a.checked_add(b).context("constant overflow")?),
                _ => None,
            },
            Self::Sub(a, b) => match (a.constant()?, b.constant()?) {
                (Some(a), Some(b)) => Some(a.checked_sub(b).context("constant overflow")?),
                _ => None,
            },
            Self::Register(_) | Self::Read(_) => None,
        })
    }

    fn compile(&self, plan: &mut CapturePlan) -> Result<()> {
        match self {
            Self::Register(index) => plan.base_register = *index,
            Self::Constant(value) => {
                plan.base_register = u32::MAX;
                plan.immediate = *value;
            }
            Self::Read(inner) => {
                inner.compile(plan)?;
                ensure!(
                    (plan.read_count as usize) < MAX_READS,
                    "dereference depth exceeds {MAX_READS}"
                );
                plan.reads[plan.read_count as usize] = ReadStep {
                    offset: plan.final_offset,
                    width: 8,
                    reserved: 0,
                };
                plan.read_count += 1;
                plan.final_offset = 0;
            }
            Self::Add(left, right) | Self::Sub(left, right) => {
                let subtract = matches!(self, Self::Sub(_, _));
                if let Some(value) = self.constant()? {
                    plan.base_register = u32::MAX;
                    plan.immediate = if value >= 0 {
                        u64::try_from(value).context("constant exceeds u64")?
                    } else {
                        u64::from_ne_bytes(
                            i64::try_from(value)
                                .context("constant below i64")?
                                .to_ne_bytes(),
                        )
                    };
                    return Ok(());
                }
                let (base, offset) = if let Some(value) = right.constant()? {
                    (left, i64::try_from(value).context("offset exceeds i64")?)
                } else if !subtract {
                    if let Some(value) = left.constant()? {
                        (right, i64::try_from(value).context("offset exceeds i64")?)
                    } else {
                        bail!("only one register/pointer chain is supported per expression")
                    }
                } else {
                    bail!("subtraction requires a constant right operand")
                };
                base.compile(plan)?;
                plan.final_offset = if subtract {
                    plan.final_offset.checked_sub(offset)
                } else {
                    plan.final_offset.checked_add(offset)
                }
                .context("offset overflow")?;
            }
        }
        Ok(())
    }
}

struct Parser<'a> {
    input: &'a [u8],
    position: usize,
    depth: usize,
}
impl Parser<'_> {
    fn space(&mut self) {
        while self
            .input
            .get(self.position)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.position += 1;
        }
    }
    fn consume(&mut self, byte: u8) -> bool {
        self.space();
        if self.input.get(self.position) == Some(&byte) {
            self.position += 1;
            true
        } else {
            false
        }
    }
    fn consume_word(&mut self, word: &[u8]) -> bool {
        self.space();
        if self.input[self.position..].starts_with(word) {
            self.position += word.len();
            true
        } else {
            false
        }
    }
    fn expect(&mut self, byte: u8) -> Result<()> {
        ensure!(
            self.consume(byte),
            "expected '{}' at byte {}",
            char::from(byte),
            self.position
        );
        Ok(())
    }
    fn sum(&mut self) -> Result<Node> {
        let mut value = self.unary()?;
        loop {
            if self.consume(b'+') {
                value = Node::Add(Box::new(value), Box::new(self.unary()?));
            } else if self.consume(b'-') {
                value = Node::Sub(Box::new(value), Box::new(self.unary()?));
            } else {
                return Ok(value);
            }
        }
    }
    fn unary(&mut self) -> Result<Node> {
        self.depth += 1;
        ensure!(self.depth <= 32, "expression nesting exceeds 32");
        let result = if self.consume(b'*') {
            Node::Read(Box::new(self.unary()?))
        } else if self.consume(b'-') {
            Node::Sub(Box::new(Node::Constant(0)), Box::new(self.unary()?))
        } else if self.consume(b'+') {
            self.unary()?
        } else {
            self.primary()?
        };
        self.depth -= 1;
        Ok(result)
    }
    fn primary(&mut self) -> Result<Node> {
        if self.consume(b'(') {
            let value = self.sum()?;
            self.expect(b')')?;
            return Ok(value);
        }
        self.space();
        let start = self.position;
        while self
            .input
            .get(self.position)
            .is_some_and(u8::is_ascii_alphanumeric)
        {
            self.position += 1;
        }
        ensure!(
            start != self.position,
            "expected register/number at byte {}",
            self.position
        );
        let token = std::str::from_utf8(&self.input[start..self.position])?;
        if token.as_bytes()[0].is_ascii_digit() {
            let value = if token.starts_with("0x") {
                crate::target::integer(token)?
            } else {
                let (number, multiplier) = match token.as_bytes().last().copied() {
                    Some(b'B') => (&token[..token.len() - 1], 1_u64),
                    Some(b'W') => (&token[..token.len() - 1], 2),
                    Some(b'D') => (&token[..token.len() - 1], 4),
                    Some(b'Q') => (&token[..token.len() - 1], 8),
                    _ => (token, 1),
                };
                number
                    .parse::<u64>()?
                    .checked_mul(multiplier)
                    .context("unit multiplication overflow")?
            };
            return Ok(Node::Constant(value));
        }
        let index = match token {
            "sp" => 31,
            "pc" => 32,
            "pstate" => 33,
            "fp" => 29,
            "lr" => 30,
            _ => {
                let number = token
                    .strip_prefix('x')
                    .or_else(|| token.strip_prefix('r'))
                    .context("unknown register")?;
                let index = number.parse::<u32>()?;
                ensure!(index <= 30, "register must be x0..x30/r0..r30");
                index
            }
        };
        Ok(Node::Register(index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn widths_and_units_are_independent() {
        for (unit, offset) in [("B", 1), ("W", 2), ("D", 4), ("Q", 8)] {
            let plan = format!("*(r13 + 1{unit})")
                .parse::<Expression>()
                .unwrap()
                .compile()
                .unwrap();
            assert_eq!(plan.base_register, 13);
            assert_eq!(plan.read_count, 1);
            assert_eq!(plan.reads[0].offset, offset);
            assert_eq!(plan.reads[0].width, 8);
        }
        let plan = "*(r13+1Q):u16"
            .parse::<Expression>()
            .unwrap()
            .compile()
            .unwrap();
        assert_eq!(plan.reads[0].width, 2);
    }
    #[test]
    fn nested_pointer_and_negative_offset() {
        let plan = "*(*(x0 + 8)-2W)"
            .parse::<Expression>()
            .unwrap()
            .compile()
            .unwrap();
        assert_eq!(plan.read_count, 2);
        assert_eq!(plan.reads[0].offset, 8);
        assert_eq!(plan.reads[1].offset, -4);
        let plan = "bytes(*sp, 64)"
            .parse::<Expression>()
            .unwrap()
            .compile()
            .unwrap();
        assert_eq!(plan.kind, KIND_BYTES);
        assert_eq!(plan.byte_length, 64);
    }
    #[test]
    fn rejects_unbounded_or_ambiguous_inputs() {
        for input in [
            "",
            "x31",
            "r99",
            "x0+x1",
            "*****x0",
            "bytes(x0, 4097)",
            "cstr(x0,0)",
            "*(x0+18446744073709551615Q)",
            "x0 trailing",
            "x0:u128",
        ] {
            assert!(input.parse::<Expression>().is_err(), "{input}");
        }
    }
    #[test]
    fn signed_output() {
        let e = "*x0:i8".parse::<Expression>().unwrap();
        assert_eq!(e.format_scalar(255)["decimal"], json!(-1));
        let negative = "-1:i64".parse::<Expression>().unwrap();
        assert_eq!(
            negative.format_scalar(negative.compile().unwrap().immediate)["decimal"],
            json!(-1)
        );
        let plan = "*(x13 + -1Q)"
            .parse::<Expression>()
            .unwrap()
            .compile()
            .unwrap();
        assert_eq!(plan.reads[0].offset, -8);
    }
}
