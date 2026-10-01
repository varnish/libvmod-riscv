/// RV64 integer registers used by the compiler and allocator.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum Reg {
    Zero = 0,
    Ra = 1,
    Sp = 2,
    Gp = 3,
    Tp = 4,
    T0 = 5,
    T1 = 6,
    T2 = 7,
    S0 = 8,
    S1 = 9,
    A0 = 10,
    A1 = 11,
    A2 = 12,
    A3 = 13,
    A4 = 14,
    A5 = 15,
    A6 = 16,
    A7 = 17,
    S2 = 18,
    S3 = 19,
    S4 = 20,
    S5 = 21,
    S6 = 22,
    S7 = 23,
    S8 = 24,
    S9 = 25,
    S10 = 26,
    S11 = 27,
    T3 = 28,
    T4 = 29,
    T5 = 30,
    T6 = 31,
}

impl Reg {
    pub(crate) const fn number(self) -> u8 {
        self as u8
    }
}

/// `t6` is the code generator's scratch; it must never be allocated.
pub(crate) const ALLOCATABLE_REGISTERS: [u8; 6] = [
    Reg::T0.number(),
    Reg::T1.number(),
    Reg::T2.number(),
    Reg::T3.number(),
    Reg::T4.number(),
    Reg::T5.number(),
];
