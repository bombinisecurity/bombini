use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Or(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Eq(String, Literal),
    In(String, Vec<Literal>),
    Group(Box<Expr>),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Literal {
    String(String),
    Uint(u64),
}

impl Expr {
    /// Recursively folds adjacent `Or` expressions with compatible `Eq`/`In`
    /// conditions on the same field into a single `In` expression.
    pub fn fold_or(self) -> Self {
        match self {
            Expr::Or(left, right) => {
                let left = Box::new(left.fold_or());
                let right = Box::new(right.fold_or());

                match (left.as_ref(), right.as_ref()) {
                    // Eq + Eq
                    (Expr::Eq(n1, l1), Expr::Eq(n2, l2)) if n1 == n2 => {
                        let set: HashSet<_> = [l1.clone(), l2.clone()].into();
                        Expr::In(n1.clone(), set.into_iter().collect())
                    }
                    // Eq + In
                    (Expr::Eq(n1, l1), Expr::In(n2, lits)) if n1 == n2 => {
                        let mut set: HashSet<_> = lits.iter().cloned().collect();
                        set.insert(l1.clone());
                        Expr::In(n1.clone(), set.into_iter().collect())
                    }
                    // In + Eq
                    (Expr::In(n1, lits), Expr::Eq(n2, l2)) if n1 == n2 => {
                        let mut set: HashSet<_> = lits.iter().cloned().collect();
                        set.insert(l2.clone());
                        Expr::In(n1.clone(), set.into_iter().collect())
                    }
                    // In + In
                    (Expr::In(n1, lits1), Expr::In(n2, lits2)) if n1 == n2 => {
                        let mut set: HashSet<_> = lits1.iter().cloned().collect();
                        set.extend(lits2.iter().cloned());
                        Expr::In(n1.clone(), set.into_iter().collect())
                    }
                    // Not compatible — keep as Or
                    _ => Expr::Or(left, right),
                }
            }
            Expr::And(left, right) => {
                Expr::And(Box::new(left.fold_or()), Box::new(right.fold_or()))
            }
            Expr::Not(inner) => Expr::Not(Box::new(inner.fold_or())),
            Expr::Group(inner) => inner.fold_or(),
            _ => self,
        }
    }
    pub fn optimize_ast(self) -> Self {
        self.fold_or()
    }
}
