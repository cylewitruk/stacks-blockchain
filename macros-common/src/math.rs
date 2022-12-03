#[macro_export]
macro_rules! fmin {
    ($x: expr) => ($x);
    ($x: expr, $($z: expr),+) => {{
        let y = fmin!($($z),*);
        if $x < y {
            $x
        } else {
            y
        }
    }}
}

#[macro_export]
macro_rules! fmax {
    ($x: expr) => ($x);
    ($x: expr, $($z: expr),+) => {{
        let y = fmax!($($z),*);
        if $x > y {
            $x
        } else {
            y
        }
    }}
}