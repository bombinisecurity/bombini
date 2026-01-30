#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Or(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Eq(String, Literal),
    In(String, Vec<Literal>),
    Group(Box<Expr>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    String(String),
    Uint(u64),
}
