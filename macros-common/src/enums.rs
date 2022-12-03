/// Define an iterable enum: an enum where each variant is an atomic
/// type (i.e., has no paramters), and the variants can be iterated over
/// with an Enum::ALL const
#[macro_export]
macro_rules! iterable_enum {
    ($Name:ident { $($Variant:ident,)* }) =>
    {
        pub enum $Name {
            $($Variant),*,
        }
        impl $Name {
            pub const ALL: &'static [$Name] = &[$($Name::$Variant),*];
        }
    }
}

/// Define a "named" enum, i.e., each variant corresponds
///  to a string literal, with a 1-1 mapping. You get EnumType::lookup_by_name
///  and EnumType.get_name() for free.
#[macro_export]
macro_rules! define_named_enum {
    ($Name:ident { $($Variant:ident($VarName:literal),)* }) =>
    {
        #[derive(::serde::Serialize, ::serde::Deserialize, Debug, Hash, PartialEq, Eq, Copy, Clone)]
        pub enum $Name {
            $($Variant),*,
        }
        impl $Name {
            pub const ALL: &'static [$Name] = &[$($Name::$Variant),*];
            pub const ALL_NAMES: &'static [&'static str] = &[$($VarName),*];

            pub fn lookup_by_name(name: &str) -> Option<Self> {
                match name {
                    $(
                        $VarName => Some($Name::$Variant),
                    )*
                    _ => None
                }
            }

            pub fn get_name(&self) -> String {
                match self {
                    $(
                        $Name::$Variant => $VarName.to_string(),
                    )*
                }
            }

            pub fn get_name_str(&self) -> &'static str {
                match self {
                    $(
                        $Name::$Variant => $VarName,
                    )*
                }
            }
        }
        impl ::std::fmt::Display for $Name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                write!(f, "{}", self.get_name_str())
            }
        }
    }
}

/// Define a "named" enum, i.e., each variant corresponds
///  to a string literal, with a 1-1 mapping. You get EnumType::lookup_by_name
///  and EnumType.get_name() for free.
#[macro_export]
macro_rules! define_versioned_named_enum {
    ($Name:ident($VerType:ty) { $($Variant:ident($VarName:literal, $Version:expr),)* }) =>
    {
        #[derive(::serde::Serialize, ::serde::Deserialize, Debug, Hash, PartialEq, Eq, Copy, Clone)]
        pub enum $Name {
            $($Variant),*,
        }
        impl $Name {
            pub const ALL: &'static [$Name] = &[$($Name::$Variant),*];
            pub const ALL_NAMES: &'static [&'static str] = &[$($VarName),*];

            fn lookup_by_name(name: &str) -> Option<Self> {
                match name {
                    $(
                        $VarName => Some($Name::$Variant),
                    )*
                    _ => None
                }
            }

            pub fn get_version(&self) -> $VerType {
                match self {
                    $(
                        $Name::$Variant => $Version,
                    )*
                }
            }

            pub fn get_name(&self) -> String {
                match self {
                    $(
                        $Name::$Variant => $VarName.to_string(),
                    )*
                }
            }

            pub fn get_name_str(&self) -> &'static str {
                match self {
                    $(
                        $Name::$Variant => $VarName,
                    )*
                }
            }
        }
        impl ::std::fmt::Display for $Name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                write!(f, "{}", self.get_name_str())
            }
        }
    }
}

/// Define a "u8" enum
///  gives you a try_from(u8) -> Option<Self> function
#[macro_export]
macro_rules! define_u8_enum {
    ($Name:ident { $($Variant:ident = $Val:literal),+ }) =>
    {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
        #[repr(u8)]
        pub enum $Name {
            $($Variant = $Val),*,
        }
        impl $Name {
            pub const ALL: &'static [$Name] = &[$($Name::$Variant),*];

            pub fn to_u8(&self) -> u8 {
                match self {
                    $(
                        $Name::$Variant => $Val,
                    )*
                }
            }

            pub fn from_u8(v: u8) -> Option<Self> {
                match v {
                    $(
                        v if v == $Name::$Variant as u8 => Some($Name::$Variant),
                    )*
                    _ => None
                }
            }
        }
    }
}