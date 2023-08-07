use crate::arbitrary::Unstructured;
use fuzzcontract::*;
use rand::Rng;
use soroban_sdk::arbitrary::arbitrary;
use soroban_sdk::arbitrary::fuzz_catch_panic;
use soroban_sdk::arbitrary::Arbitrary;
use soroban_sdk::arbitrary::SorobanArbitrary;
use soroban_sdk::testutils::Logs;
use soroban_sdk::{Address, Bytes, Vec};
use soroban_sdk::{Env, FromVal, IntoVal, Map, String, Symbol, Val};
use std::fs::OpenOptions;
use std::io::Write;
use std::time::Instant;

mod fuzzcontract {
    soroban_sdk::contractimport!(
        file = "../contract-for-fuzz/target/wasm32-unknown-unknown/release/contract_for_fuzz.wasm"
    );
}

#[derive(Clone, Debug, arbitrary::Arbitrary)]
pub enum TypedFuzzInstructionPrototype {
    Address(TypedModAddressPrototype),
    Buf(TypedModBufPrototype),
    Call(TypedModCallPrototype),
    Context(TypedModContextPrototype),
    Crypto(TypedModCryptoPrototype),
    Int(TypedModIntPrototype),
    Ledger(TypedModLedgerPrototype),
    Map(TypedModMapPrototype),
    Prng(TypedModPrngPrototype),
    Test,
    Vec(TypedModVecPrototype),
}

#[derive(Clone, Debug, arbitrary::Arbitrary)]
pub enum TypedModAddressPrototype {
    AccountPublicKeyToAddress(<Bytes as SorobanArbitrary>::Prototype),
    AddressToAccountPublicKey(<Address as SorobanArbitrary>::Prototype),
    AddressToContractId(<Address as SorobanArbitrary>::Prototype),
    AuthorizeAsCurrContract(<Vec<Val> as SorobanArbitrary>::Prototype),
    ContractIdToAddress(<Bytes as SorobanArbitrary>::Prototype),
    RequireAuth(<Address as SorobanArbitrary>::Prototype),
    RequireAuthForArgs(
        <Address as SorobanArbitrary>::Prototype,
        <Vec<Val> as SorobanArbitrary>::Prototype,
    ),
}

#[derive(Clone, Debug, arbitrary::Arbitrary)]
pub enum TypedModBufPrototype {
    BytesAppend(
        <Bytes as SorobanArbitrary>::Prototype,
        <Bytes as SorobanArbitrary>::Prototype,
    ),
    BytesBack(<Bytes as SorobanArbitrary>::Prototype),
    BytesCopyFromLinearMemory(
        <Bytes as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    BytesCopyToLinearMemory(
        <Bytes as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    BytesDel(
        <Bytes as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    BytesFront(<Bytes as SorobanArbitrary>::Prototype),
    BytesGet(
        <Bytes as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    BytesInsert(
        <Bytes as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    BytesLen(<Bytes as SorobanArbitrary>::Prototype),
    BytesNew,
    BytesNewFromLinearMemory(
        <u32 as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    BytesPop(<Bytes as SorobanArbitrary>::Prototype),
    BytesPush(
        <Bytes as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    BytesPut(
        <Bytes as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    BytesSlice(
        <Bytes as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    DeserializeFromBytes(<Bytes as SorobanArbitrary>::Prototype),
    SerializeToBytes(<Val as SorobanArbitrary>::Prototype),
    StringCopyToLinearMemory(
        <String as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    StringLen(<String as SorobanArbitrary>::Prototype),
    StringNewFromLinearMemory(
        <u32 as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    SymbolCopyToLinearMemory(
        <Symbol as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    SymbolIndexInLinearMemory(
        <Symbol as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    SymbolLen(<Symbol as SorobanArbitrary>::Prototype),
    SymbolNewFromLinearMemory(
        <u32 as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
}

#[derive(Clone, Debug, arbitrary::Arbitrary)]
pub enum TypedModCallPrototype {
    Call(
        <Address as SorobanArbitrary>::Prototype,
        <Symbol as SorobanArbitrary>::Prototype,
        <Vec<Val> as SorobanArbitrary>::Prototype,
    ),
    TryCall(
        <Address as SorobanArbitrary>::Prototype,
        <Symbol as SorobanArbitrary>::Prototype,
        <Vec<Val> as SorobanArbitrary>::Prototype,
    ),
}

#[derive(Clone, Debug, arbitrary::Arbitrary)]
pub enum TypedModContextPrototype {
    ContractEvent(
        <Vec<Val> as SorobanArbitrary>::Prototype,
        <Val as SorobanArbitrary>::Prototype,
    ),
    FailWithError(<Val as SorobanArbitrary>::Prototype),
    GetCurrentCallStack,
    GetCurrentContractAddress,
    GetInvokingContract,
    GetLedgerNetworkId,
    GetLedgerSequence,
    GetLedgerTimestamp,
    GetLedgerVersion,
    LogFromLinearMemory(
        <u32 as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    ObjCmp(
        <Val as SorobanArbitrary>::Prototype,
        <Val as SorobanArbitrary>::Prototype,
    ),
}

#[derive(Clone, Debug, arbitrary::Arbitrary)]
pub enum TypedModCryptoPrototype {
    ComputeHashKeccak256(<Bytes as SorobanArbitrary>::Prototype),
    ComputeHashSha256(<Bytes as SorobanArbitrary>::Prototype),
    RecoverKeyEcdsaSecp256k1(
        <Bytes as SorobanArbitrary>::Prototype,
        <Bytes as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    VerifySigEd25519(
        <Bytes as SorobanArbitrary>::Prototype,
        <Bytes as SorobanArbitrary>::Prototype,
        <Bytes as SorobanArbitrary>::Prototype,
    ),
}

#[derive(Clone, Debug, arbitrary::Arbitrary)]
pub enum TypedModIntPrototype {
    DurationObjFromU64(<u64 as SorobanArbitrary>::Prototype),
    DurationObjToU64(<Val as SorobanArbitrary>::Prototype),
    I256Add(
        <Val as SorobanArbitrary>::Prototype,
        <Val as SorobanArbitrary>::Prototype,
    ),
    I256Div(
        <Val as SorobanArbitrary>::Prototype,
        <Val as SorobanArbitrary>::Prototype,
    ),
    I256Mul(
        <Val as SorobanArbitrary>::Prototype,
        <Val as SorobanArbitrary>::Prototype,
    ),
    I256ObjFromBeBytes(<Bytes as SorobanArbitrary>::Prototype),
    I256ObjToBeBytes(<Val as SorobanArbitrary>::Prototype),
    I256Pow(
        <Val as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    I256Shl(
        <Val as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    I256Shr(
        <Val as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    I256Sub(
        <Val as SorobanArbitrary>::Prototype,
        <Val as SorobanArbitrary>::Prototype,
    ),
    ObjFromI64(<i64 as SorobanArbitrary>::Prototype),
    ObjFromI128Pieces(
        <i64 as SorobanArbitrary>::Prototype,
        <u64 as SorobanArbitrary>::Prototype,
    ),
    ObjFromI256Pieces(
        <i64 as SorobanArbitrary>::Prototype,
        <u64 as SorobanArbitrary>::Prototype,
        <u64 as SorobanArbitrary>::Prototype,
        <u64 as SorobanArbitrary>::Prototype,
    ),
    ObjFromU64(<u64 as SorobanArbitrary>::Prototype),
    ObjFromU128Pieces(
        <u64 as SorobanArbitrary>::Prototype,
        <u64 as SorobanArbitrary>::Prototype,
    ),
    ObjFromU256Pieces(
        <u64 as SorobanArbitrary>::Prototype,
        <u64 as SorobanArbitrary>::Prototype,
        <u64 as SorobanArbitrary>::Prototype,
        <u64 as SorobanArbitrary>::Prototype,
    ),
    ObjToI64(<i64 as SorobanArbitrary>::Prototype),
    ObjToI128Hi64(<i128 as SorobanArbitrary>::Prototype),
    ObjToI128Lo64(<i128 as SorobanArbitrary>::Prototype),
    ObjToI256HiHi(<Val as SorobanArbitrary>::Prototype),
    ObjToI256HiLo(<Val as SorobanArbitrary>::Prototype),
    ObjToI256LoHi(<Val as SorobanArbitrary>::Prototype),
    ObjToI256LoLo(<Val as SorobanArbitrary>::Prototype),
    ObjToU64(<u64 as SorobanArbitrary>::Prototype),
    ObjToU128Hi64(<u128 as SorobanArbitrary>::Prototype),
    ObjToU128Lo64(<u128 as SorobanArbitrary>::Prototype),
    ObjToU256HiHi(<Val as SorobanArbitrary>::Prototype),
    ObjToU256HiLo(<Val as SorobanArbitrary>::Prototype),
    ObjToU256LoHi(<Val as SorobanArbitrary>::Prototype),
    ObjToU256LoLo(<Val as SorobanArbitrary>::Prototype),
    TimepointObjFromU64(<u64 as SorobanArbitrary>::Prototype),
    TimepointObjToU64(<Val as SorobanArbitrary>::Prototype),
    U256Add(
        <Val as SorobanArbitrary>::Prototype,
        <Val as SorobanArbitrary>::Prototype,
    ),
    U256Div(
        <Val as SorobanArbitrary>::Prototype,
        <Val as SorobanArbitrary>::Prototype,
    ),
    U256Mul(
        <Val as SorobanArbitrary>::Prototype,
        <Val as SorobanArbitrary>::Prototype,
    ),
    U256ValFromBeBytes(<Bytes as SorobanArbitrary>::Prototype),
    U256ValToBeBytes(<Val as SorobanArbitrary>::Prototype),
    U256Pow(
        <Val as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    U256Shl(
        <Val as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    U256Shr(
        <Val as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    U256Sub(
        <Val as SorobanArbitrary>::Prototype,
        <Val as SorobanArbitrary>::Prototype,
    ),
}

#[derive(Clone, Debug, arbitrary::Arbitrary)]
pub enum TypedModLedgerPrototype {
    BumpContractData(
        <Val as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    CreateAssetContract(<Bytes as SorobanArbitrary>::Prototype),
    CreateContract(
        <Address as SorobanArbitrary>::Prototype,
        <Bytes as SorobanArbitrary>::Prototype,
        <Bytes as SorobanArbitrary>::Prototype,
    ),
    DelContractData(<Val as SorobanArbitrary>::Prototype),
    GetAssetContractId(<Bytes as SorobanArbitrary>::Prototype),
    GetContractData(<Val as SorobanArbitrary>::Prototype),
    GetContractId(
        <Address as SorobanArbitrary>::Prototype,
        <Bytes as SorobanArbitrary>::Prototype,
    ),
    HasContractData(<Val as SorobanArbitrary>::Prototype),
    PutContractData(
        <Val as SorobanArbitrary>::Prototype,
        <Val as SorobanArbitrary>::Prototype,
        <Val as SorobanArbitrary>::Prototype,
    ),
    UpdateCurrentContractWasm(<Bytes as SorobanArbitrary>::Prototype),
    UploadWasm(<Bytes as SorobanArbitrary>::Prototype),
}

#[derive(Clone, Debug, arbitrary::Arbitrary)]
pub enum TypedModMapPrototype {
    MapDel(
        <Map<Val, Val> as SorobanArbitrary>::Prototype,
        <Val as SorobanArbitrary>::Prototype,
    ),
    MapGet(
        <Map<Val, Val> as SorobanArbitrary>::Prototype,
        <Val as SorobanArbitrary>::Prototype,
    ),
    MapHas(
        <Map<Val, Val> as SorobanArbitrary>::Prototype,
        <Val as SorobanArbitrary>::Prototype,
    ),
    MapKeys(<Map<Val, Val> as SorobanArbitrary>::Prototype),
    MapLen(<Map<Val, Val> as SorobanArbitrary>::Prototype),
    MapMaxKey(<Map<Val, Val> as SorobanArbitrary>::Prototype),
    MapMinKey(<Map<Val, Val> as SorobanArbitrary>::Prototype),
    MapNew,
    MapNewFromLinearMemory(
        <u32 as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    MapNextKey(
        <Map<Val, Val> as SorobanArbitrary>::Prototype,
        <Val as SorobanArbitrary>::Prototype,
    ),
    MapPrevKey(
        <Map<Val, Val> as SorobanArbitrary>::Prototype,
        <Val as SorobanArbitrary>::Prototype,
    ),
    MapPut(
        <Map<Val, Val> as SorobanArbitrary>::Prototype,
        <Val as SorobanArbitrary>::Prototype,
        <Val as SorobanArbitrary>::Prototype,
    ),
    MapUnpackToLinearMemory(
        <Map<Val, Val> as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    MapValues(<Map<Val, Val> as SorobanArbitrary>::Prototype),
}

#[derive(Clone, Debug, arbitrary::Arbitrary)]
pub enum TypedModPrngPrototype {
    PrngBytesNew(u32),
    PrngReseed(<Bytes as SorobanArbitrary>::Prototype),
    PrngU64InInclusiveRange(u64, u64),
    PrngVecShuffle(<Vec<Val> as SorobanArbitrary>::Prototype),
}

#[derive(Clone, Debug, arbitrary::Arbitrary)]
pub enum TypedModVecPrototype {
    VecAppend(
        <Vec<Val> as SorobanArbitrary>::Prototype,
        <Vec<Val> as SorobanArbitrary>::Prototype,
    ),
    VecBack(<Vec<Val> as SorobanArbitrary>::Prototype),
    VecBinarySearch(
        <Vec<Val> as SorobanArbitrary>::Prototype,
        <Val as SorobanArbitrary>::Prototype,
    ),
    VecDel(
        <Vec<Val> as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    VecFirstIndexOf(
        <Vec<Val> as SorobanArbitrary>::Prototype,
        <Val as SorobanArbitrary>::Prototype,
    ),
    VecFront(<Vec<Val> as SorobanArbitrary>::Prototype),
    VecGet(
        <Vec<Val> as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    VecInsert(
        <Vec<Val> as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
        <Val as SorobanArbitrary>::Prototype,
    ),
    VecLastIndexOf(
        <Vec<Val> as SorobanArbitrary>::Prototype,
        <Val as SorobanArbitrary>::Prototype,
    ),
    VecLen(<Vec<Val> as SorobanArbitrary>::Prototype),
    VecNew(<Val as SorobanArbitrary>::Prototype),
    VecNewFromLinearMemory(
        <u32 as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    VecPopBack(<Vec<Val> as SorobanArbitrary>::Prototype),
    VecPopFront(<Vec<Val> as SorobanArbitrary>::Prototype),
    VecPushBack(
        <Vec<Val> as SorobanArbitrary>::Prototype,
        <Val as SorobanArbitrary>::Prototype,
    ),
    VecPushFront(
        <Vec<Val> as SorobanArbitrary>::Prototype,
        <Val as SorobanArbitrary>::Prototype,
    ),
    VecPut(
        <Vec<Val> as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
        <Val as SorobanArbitrary>::Prototype,
    ),
    VecSlice(
        <Vec<Val> as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
    VecUnpackToLinearMemory(
        <Vec<Val> as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
        <u32 as SorobanArbitrary>::Prototype,
    ),
}

impl TypedFuzzInstructionPrototype {
    fn to_guest(&self, env: &Env) -> TypedFuzzInstruction {
        match self {
            TypedFuzzInstructionPrototype::Address(v) => match v {
                TypedModAddressPrototype::AccountPublicKeyToAddress(v) => {
                    let v = Bytes::from_val(env, v);
                    TypedFuzzInstruction::Address(TypedModAddress::AccountPublicKeyToAddress(v))
                }
                TypedModAddressPrototype::AddressToAccountPublicKey(v) => {
                    let v = Address::from_val(env, v);
                    TypedFuzzInstruction::Address(TypedModAddress::AddressToAccountPublicKey(v))
                }
                TypedModAddressPrototype::AddressToContractId(v) => {
                    let v = Address::from_val(env, v);
                    TypedFuzzInstruction::Address(TypedModAddress::AddressToContractId(v))
                }
                TypedModAddressPrototype::AuthorizeAsCurrContract(v) => {
                    let v = Vec::<Val>::from_val(env, v);
                    TypedFuzzInstruction::Address(TypedModAddress::AuthorizeAsCurrContract(v))
                }
                TypedModAddressPrototype::ContractIdToAddress(v) => {
                    let v = Bytes::from_val(env, v);
                    TypedFuzzInstruction::Address(TypedModAddress::ContractIdToAddress(v))
                }
                TypedModAddressPrototype::RequireAuth(v) => {
                    let v = Address::from_val(env, v);
                    TypedFuzzInstruction::Address(TypedModAddress::RequireAuth(v))
                }
                TypedModAddressPrototype::RequireAuthForArgs(v_0, v_1) => {
                    let v_0 = Address::from_val(env, v_0);
                    let v_1 = Vec::<Val>::from_val(env, v_1);
                    TypedFuzzInstruction::Address(TypedModAddress::RequireAuthForArgs(v_0, v_1))
                }
            },
            TypedFuzzInstructionPrototype::Buf(v) => match v {
                TypedModBufPrototype::BytesAppend(v_0, v_1) => TypedFuzzInstruction::Buf(
                    TypedModBuf::BytesAppend(v_0.into_val(env), v_1.into_val(env)),
                ),
                TypedModBufPrototype::BytesBack(v) => {
                    TypedFuzzInstruction::Buf(TypedModBuf::BytesBack(v.into_val(env)))
                }
                TypedModBufPrototype::BytesCopyFromLinearMemory(v_0, v_1, v_2, v_3) => {
                    let v_0 = Bytes::from_val(env, v_0);
                    TypedFuzzInstruction::Buf(TypedModBuf::BytesCopyFromLinearMemory(
                        v_0, *v_1, *v_2, *v_3,
                    ))
                }
                TypedModBufPrototype::BytesCopyToLinearMemory(v_0, v_1, v_2, v_3) => {
                    let v_0 = Bytes::from_val(env, v_0);
                    TypedFuzzInstruction::Buf(TypedModBuf::BytesCopyToLinearMemory(
                        v_0, *v_1, *v_2, *v_3,
                    ))
                }
                TypedModBufPrototype::BytesDel(v_0, v_1) => {
                    let v_0 = Bytes::from_val(env, v_0);
                    TypedFuzzInstruction::Buf(TypedModBuf::BytesDel(v_0, *v_1))
                }
                TypedModBufPrototype::BytesFront(v) => {
                    let v = Bytes::from_val(env, v);
                    TypedFuzzInstruction::Buf(TypedModBuf::BytesFront(v))
                }
                TypedModBufPrototype::BytesGet(v_0, v_1) => {
                    let v_0 = Bytes::from_val(env, v_0);
                    TypedFuzzInstruction::Buf(TypedModBuf::BytesGet(v_0, *v_1))
                }
                TypedModBufPrototype::BytesInsert(v_0, v_1, v_2) => {
                    let v_0 = Bytes::from_val(env, v_0);
                    TypedFuzzInstruction::Buf(TypedModBuf::BytesInsert(v_0, *v_1, *v_2))
                }
                TypedModBufPrototype::BytesLen(v) => {
                    let v = Bytes::from_val(env, v);
                    TypedFuzzInstruction::Buf(TypedModBuf::BytesLen(v))
                }
                TypedModBufPrototype::BytesNew => TypedFuzzInstruction::Buf(TypedModBuf::BytesNew),
                TypedModBufPrototype::BytesNewFromLinearMemory(v_0, v_1) => {
                    TypedFuzzInstruction::Buf(TypedModBuf::BytesNewFromLinearMemory(*v_0, *v_1))
                }
                TypedModBufPrototype::BytesPop(v) => {
                    let v = Bytes::from_val(env, v);
                    TypedFuzzInstruction::Buf(TypedModBuf::BytesPop(v))
                }
                TypedModBufPrototype::BytesPush(v_0, v_1) => {
                    let v_0 = Bytes::from_val(env, v_0);
                    TypedFuzzInstruction::Buf(TypedModBuf::BytesPush(v_0, *v_1))
                }
                TypedModBufPrototype::BytesPut(v_0, v_1, v_2) => {
                    let v_0 = Bytes::from_val(env, v_0);
                    TypedFuzzInstruction::Buf(TypedModBuf::BytesPut(v_0, *v_1, *v_2))
                }
                TypedModBufPrototype::BytesSlice(v_0, v_1, v_2) => {
                    let v_0 = Bytes::from_val(env, v_0);
                    TypedFuzzInstruction::Buf(TypedModBuf::BytesSlice(v_0, *v_1, *v_2))
                }
                TypedModBufPrototype::DeserializeFromBytes(v) => {
                    let v = Bytes::from_val(env, v);
                    TypedFuzzInstruction::Buf(TypedModBuf::DeserializeFromBytes(v))
                }
                TypedModBufPrototype::SerializeToBytes(v) => {
                    let v = Val::from_val(env, v);
                    TypedFuzzInstruction::Buf(TypedModBuf::SerializeToBytes(FakeVal(
                        v.get_payload(),
                    )))
                }
                TypedModBufPrototype::StringCopyToLinearMemory(v_0, v_1, v_2, v_3) => {
                    let v_0 = String::from_val(env, v_0);
                    TypedFuzzInstruction::Buf(TypedModBuf::StringCopyToLinearMemory(
                        v_0, *v_1, *v_2, *v_3,
                    ))
                }
                TypedModBufPrototype::StringLen(v) => {
                    let v = String::from_val(env, v);
                    TypedFuzzInstruction::Buf(TypedModBuf::StringLen(v))
                }
                TypedModBufPrototype::StringNewFromLinearMemory(v_0, v_1) => {
                    TypedFuzzInstruction::Buf(TypedModBuf::StringNewFromLinearMemory(*v_0, *v_1))
                }
                TypedModBufPrototype::SymbolCopyToLinearMemory(v_0, v_1, v_2, v_3) => {
                    let v_0 = Symbol::from_val(env, v_0);
                    TypedFuzzInstruction::Buf(TypedModBuf::SymbolCopyToLinearMemory(
                        v_0, *v_1, *v_2, *v_3,
                    ))
                }
                TypedModBufPrototype::SymbolIndexInLinearMemory(v_0, v_1, v_2) => {
                    let v_0 = Symbol::from_val(env, v_0);
                    TypedFuzzInstruction::Buf(TypedModBuf::SymbolIndexInLinearMemory(
                        v_0, *v_1, *v_2,
                    ))
                }
                TypedModBufPrototype::SymbolLen(v) => {
                    let v = Symbol::from_val(env, v);
                    TypedFuzzInstruction::Buf(TypedModBuf::SymbolLen(v))
                }
                TypedModBufPrototype::SymbolNewFromLinearMemory(v_0, v_1) => {
                    TypedFuzzInstruction::Buf(TypedModBuf::SymbolNewFromLinearMemory(*v_0, *v_1))
                }
            },
            TypedFuzzInstructionPrototype::Call(v) => match v {
                TypedModCallPrototype::Call(v_0, v_1, v_2) => {
                    let v_0 = Address::from_val(env, v_0);
                    let v_1 = Symbol::from_val(env, v_1);
                    let v_2 = Vec::<Val>::from_val(env, v_2);
                    TypedFuzzInstruction::Call(TypedModCall::Call(v_0, v_1, v_2))
                }
                TypedModCallPrototype::TryCall(v_0, v_1, v_2) => {
                    let v_0 = Address::from_val(env, v_0);
                    let v_1 = Symbol::from_val(env, v_1);
                    let v_2 = Vec::<Val>::from_val(env, v_2);
                    TypedFuzzInstruction::Call(TypedModCall::TryCall(v_0, v_1, v_2))
                }
            },
            TypedFuzzInstructionPrototype::Context(v) => match v {
                TypedModContextPrototype::ContractEvent(v_0, v_1) => {
                    let v_0 = Vec::<Val>::from_val(env, v_0);
                    let v_1 = Val::from_val(env, v_1);
                    TypedFuzzInstruction::Context(TypedModContext::ContractEvent(
                        v_0,
                        FakeVal(v_1.get_payload()),
                    ))
                }
                TypedModContextPrototype::FailWithError(v) => {
                    let v = Val::from_val(env, v);
                    TypedFuzzInstruction::Context(TypedModContext::FailWithError(FakeVal(
                        v.get_payload(),
                    )))
                }
                TypedModContextPrototype::GetCurrentCallStack => {
                    TypedFuzzInstruction::Context(TypedModContext::GetCurrentCallStack)
                }
                TypedModContextPrototype::GetCurrentContractAddress => {
                    TypedFuzzInstruction::Context(TypedModContext::GetCurrentContractAddress)
                }
                TypedModContextPrototype::GetInvokingContract => {
                    TypedFuzzInstruction::Context(TypedModContext::GetInvokingContract)
                }
                TypedModContextPrototype::GetLedgerNetworkId => {
                    TypedFuzzInstruction::Context(TypedModContext::GetLedgerNetworkId)
                }
                TypedModContextPrototype::GetLedgerSequence => {
                    TypedFuzzInstruction::Context(TypedModContext::GetLedgerSequence)
                }
                TypedModContextPrototype::GetLedgerTimestamp => {
                    TypedFuzzInstruction::Context(TypedModContext::GetLedgerTimestamp)
                }
                TypedModContextPrototype::GetLedgerVersion => {
                    TypedFuzzInstruction::Context(TypedModContext::GetLedgerVersion)
                }
                TypedModContextPrototype::LogFromLinearMemory(v_0, v_1, v_2, v_3) => {
                    TypedFuzzInstruction::Context(TypedModContext::LogFromLinearMemory(
                        *v_0, *v_1, *v_2, *v_3,
                    ))
                }
                TypedModContextPrototype::ObjCmp(v_0, v_1) => {
                    let v_0 = Val::from_val(env, v_0);
                    let v_1 = Val::from_val(env, v_1);
                    TypedFuzzInstruction::Context(TypedModContext::ObjCmp(
                        FakeVal(v_0.get_payload()),
                        FakeVal(v_1.get_payload()),
                    ))
                }
            },
            TypedFuzzInstructionPrototype::Crypto(v) => match v {
                TypedModCryptoPrototype::ComputeHashKeccak256(v) => {
                    let v = Bytes::from_val(env, v);
                    TypedFuzzInstruction::Crypto(TypedModCrypto::ComputeHashKeccak256(v))
                }
                TypedModCryptoPrototype::ComputeHashSha256(v) => {
                    let v = Bytes::from_val(env, v);
                    TypedFuzzInstruction::Crypto(TypedModCrypto::ComputeHashSha256(v))
                }
                TypedModCryptoPrototype::RecoverKeyEcdsaSecp256k1(v_0, v_1, v_2) => {
                    let v_0 = Bytes::from_val(env, v_0);
                    let v_1 = Bytes::from_val(env, v_1);
                    TypedFuzzInstruction::Crypto(TypedModCrypto::RecoverKeyEcdsaSecp256k1(
                        v_0, v_1, *v_2,
                    ))
                }
                TypedModCryptoPrototype::VerifySigEd25519(v_0, v_1, v_2) => {
                    let v_0 = Bytes::from_val(env, v_0);
                    let v_1 = Bytes::from_val(env, v_1);
                    let v_2 = Bytes::from_val(env, v_2);
                    TypedFuzzInstruction::Crypto(TypedModCrypto::VerifySigEd25519(v_0, v_1, v_2))
                }
            },
            TypedFuzzInstructionPrototype::Int(v) => match v {
                TypedModIntPrototype::DurationObjFromU64(v) => {
                    TypedFuzzInstruction::Int(TypedModInt::DurationObjFromU64(*v))
                }
                TypedModIntPrototype::DurationObjToU64(v) => {
                    let v = Val::from_val(env, v);
                    TypedFuzzInstruction::Int(TypedModInt::DurationObjToU64(FakeVal(
                        v.get_payload(),
                    )))
                }
                TypedModIntPrototype::I256Add(v_0, v_1) => {
                    let v_0 = Val::from_val(env, v_0);
                    let v_1 = Val::from_val(env, v_1);
                    TypedFuzzInstruction::Int(TypedModInt::I256Add(
                        FakeVal(v_0.get_payload()),
                        FakeVal(v_1.get_payload()),
                    ))
                }
                TypedModIntPrototype::I256Div(v_0, v_1) => {
                    let v_0 = Val::from_val(env, v_0);
                    let v_1 = Val::from_val(env, v_1);
                    TypedFuzzInstruction::Int(TypedModInt::I256Div(
                        FakeVal(v_0.get_payload()),
                        FakeVal(v_1.get_payload()),
                    ))
                }
                TypedModIntPrototype::I256Mul(v_0, v_1) => {
                    let v_0 = Val::from_val(env, v_0);
                    let v_1 = Val::from_val(env, v_1);
                    TypedFuzzInstruction::Int(TypedModInt::I256Mul(
                        FakeVal(v_0.get_payload()),
                        FakeVal(v_1.get_payload()),
                    ))
                }
                TypedModIntPrototype::I256ObjFromBeBytes(v) => {
                    let v = Bytes::from_val(env, v);
                    TypedFuzzInstruction::Int(TypedModInt::I256ObjFromBeBytes(v))
                }
                TypedModIntPrototype::I256ObjToBeBytes(v) => {
                    let v = Val::from_val(env, v);
                    TypedFuzzInstruction::Int(TypedModInt::I256ObjToBeBytes(FakeVal(
                        v.get_payload(),
                    )))
                }
                TypedModIntPrototype::I256Pow(v_0, v_1) => {
                    let v_0 = Val::from_val(env, v_0);
                    TypedFuzzInstruction::Int(TypedModInt::I256Pow(
                        FakeVal(v_0.get_payload()),
                        *v_1,
                    ))
                }
                TypedModIntPrototype::I256Shl(v_0, v_1) => {
                    let v_0 = Val::from_val(env, v_0);
                    TypedFuzzInstruction::Int(TypedModInt::I256Shl(
                        FakeVal(v_0.get_payload()),
                        *v_1,
                    ))
                }
                TypedModIntPrototype::I256Shr(v_0, v_1) => {
                    let v_0 = Val::from_val(env, v_0);
                    TypedFuzzInstruction::Int(TypedModInt::I256Shr(
                        FakeVal(v_0.get_payload()),
                        *v_1,
                    ))
                }
                TypedModIntPrototype::I256Sub(v_0, v_1) => {
                    let v_0 = Val::from_val(env, v_0);
                    let v_1 = Val::from_val(env, v_1);
                    TypedFuzzInstruction::Int(TypedModInt::I256Sub(
                        FakeVal(v_0.get_payload()),
                        FakeVal(v_1.get_payload()),
                    ))
                }
                TypedModIntPrototype::ObjFromI64(v) => {
                    TypedFuzzInstruction::Int(TypedModInt::ObjFromI64(*v))
                }
                TypedModIntPrototype::ObjFromI128Pieces(v_0, v_1) => {
                    TypedFuzzInstruction::Int(TypedModInt::ObjFromI128Pieces(*v_0, *v_1))
                }
                TypedModIntPrototype::ObjFromI256Pieces(v_0, v_1, v_2, v_3) => {
                    TypedFuzzInstruction::Int(TypedModInt::ObjFromI256Pieces(
                        *v_0, *v_1, *v_2, *v_3,
                    ))
                }
                TypedModIntPrototype::ObjFromU64(v) => {
                    TypedFuzzInstruction::Int(TypedModInt::ObjFromU64(*v))
                }
                TypedModIntPrototype::ObjFromU128Pieces(v_0, v_1) => {
                    TypedFuzzInstruction::Int(TypedModInt::ObjFromU128Pieces(*v_0, *v_1))
                }
                TypedModIntPrototype::ObjFromU256Pieces(v_0, v_1, v_2, v_3) => {
                    TypedFuzzInstruction::Int(TypedModInt::ObjFromU256Pieces(
                        *v_0, *v_1, *v_2, *v_3,
                    ))
                }
                TypedModIntPrototype::ObjToI64(v) => {
                    TypedFuzzInstruction::Int(TypedModInt::ObjToI64(*v))
                }
                TypedModIntPrototype::ObjToI128Hi64(v) => {
                    TypedFuzzInstruction::Int(TypedModInt::ObjToI128Hi64(*v))
                }
                TypedModIntPrototype::ObjToI128Lo64(v) => {
                    TypedFuzzInstruction::Int(TypedModInt::ObjToI128Lo64(*v))
                }
                TypedModIntPrototype::ObjToI256HiHi(v) => {
                    let v = Val::from_val(env, v);
                    TypedFuzzInstruction::Int(TypedModInt::ObjToI256HiHi(FakeVal(v.get_payload())))
                }
                TypedModIntPrototype::ObjToI256HiLo(v) => {
                    let v = Val::from_val(env, v);
                    TypedFuzzInstruction::Int(TypedModInt::ObjToI256HiLo(FakeVal(v.get_payload())))
                }
                TypedModIntPrototype::ObjToI256LoHi(v) => {
                    let v = Val::from_val(env, v);
                    TypedFuzzInstruction::Int(TypedModInt::ObjToI256LoHi(FakeVal(v.get_payload())))
                }
                TypedModIntPrototype::ObjToI256LoLo(v) => {
                    let v = Val::from_val(env, v);
                    TypedFuzzInstruction::Int(TypedModInt::ObjToI256LoLo(FakeVal(v.get_payload())))
                }
                TypedModIntPrototype::ObjToU64(v) => {
                    TypedFuzzInstruction::Int(TypedModInt::ObjToU64(*v))
                }
                TypedModIntPrototype::ObjToU128Hi64(v) => {
                    TypedFuzzInstruction::Int(TypedModInt::ObjToU128Hi64(*v))
                }
                TypedModIntPrototype::ObjToU128Lo64(v) => {
                    TypedFuzzInstruction::Int(TypedModInt::ObjToU128Lo64(*v))
                }
                TypedModIntPrototype::ObjToU256HiHi(v) => {
                    let v = Val::from_val(env, v);
                    TypedFuzzInstruction::Int(TypedModInt::ObjToU256HiHi(FakeVal(v.get_payload())))
                }
                TypedModIntPrototype::ObjToU256HiLo(v) => {
                    let v = Val::from_val(env, v);
                    TypedFuzzInstruction::Int(TypedModInt::ObjToU256HiLo(FakeVal(v.get_payload())))
                }
                TypedModIntPrototype::ObjToU256LoHi(v) => {
                    let v = Val::from_val(env, v);
                    TypedFuzzInstruction::Int(TypedModInt::ObjToU256LoHi(FakeVal(v.get_payload())))
                }
                TypedModIntPrototype::ObjToU256LoLo(v) => {
                    let v = Val::from_val(env, v);
                    TypedFuzzInstruction::Int(TypedModInt::ObjToU256LoLo(FakeVal(v.get_payload())))
                }
                TypedModIntPrototype::TimepointObjFromU64(v) => {
                    TypedFuzzInstruction::Int(TypedModInt::TimepointObjFromU64(*v))
                }
                TypedModIntPrototype::TimepointObjToU64(v) => {
                    let v = Val::from_val(env, v);
                    TypedFuzzInstruction::Int(TypedModInt::TimepointObjToU64(FakeVal(
                        v.get_payload(),
                    )))
                }
                TypedModIntPrototype::U256Add(v_0, v_1) => {
                    let v_0 = Val::from_val(env, v_0);
                    let v_1 = Val::from_val(env, v_1);
                    TypedFuzzInstruction::Int(TypedModInt::U256Add(
                        FakeVal(v_0.get_payload()),
                        FakeVal(v_1.get_payload()),
                    ))
                }
                TypedModIntPrototype::U256Div(v_0, v_1) => {
                    let v_0 = Val::from_val(env, v_0);
                    let v_1 = Val::from_val(env, v_1);
                    TypedFuzzInstruction::Int(TypedModInt::U256Div(
                        FakeVal(v_0.get_payload()),
                        FakeVal(v_1.get_payload()),
                    ))
                }
                TypedModIntPrototype::U256Mul(v_0, v_1) => {
                    let v_0 = Val::from_val(env, v_0);
                    let v_1 = Val::from_val(env, v_1);
                    TypedFuzzInstruction::Int(TypedModInt::U256Mul(
                        FakeVal(v_0.get_payload()),
                        FakeVal(v_1.get_payload()),
                    ))
                }
                TypedModIntPrototype::U256ValFromBeBytes(v) => {
                    let v = Bytes::from_val(env, v);
                    TypedFuzzInstruction::Int(TypedModInt::U256ValFromBeBytes(v))
                }
                TypedModIntPrototype::U256ValToBeBytes(v) => {
                    let v = Val::from_val(env, v);
                    TypedFuzzInstruction::Int(TypedModInt::U256ValToBeBytes(FakeVal(
                        v.get_payload(),
                    )))
                }
                TypedModIntPrototype::U256Pow(v_0, v_1) => {
                    let v_0 = Val::from_val(env, v_0);
                    TypedFuzzInstruction::Int(TypedModInt::U256Pow(
                        FakeVal(v_0.get_payload()),
                        *v_1,
                    ))
                }
                TypedModIntPrototype::U256Shl(v_0, v_1) => {
                    let v_0 = Val::from_val(env, v_0);
                    TypedFuzzInstruction::Int(TypedModInt::U256Shl(
                        FakeVal(v_0.get_payload()),
                        *v_1,
                    ))
                }
                TypedModIntPrototype::U256Shr(v_0, v_1) => {
                    let v_0 = Val::from_val(env, v_0);
                    TypedFuzzInstruction::Int(TypedModInt::U256Shr(
                        FakeVal(v_0.get_payload()),
                        *v_1,
                    ))
                }
                TypedModIntPrototype::U256Sub(v_0, v_1) => {
                    let v_0 = Val::from_val(env, v_0);
                    let v_1 = Val::from_val(env, v_1);
                    TypedFuzzInstruction::Int(TypedModInt::U256Sub(
                        FakeVal(v_0.get_payload()),
                        FakeVal(v_1.get_payload()),
                    ))
                }
            },
            TypedFuzzInstructionPrototype::Ledger(v) => match v {
                TypedModLedgerPrototype::BumpContractData(v_0, v_1) => {
                    let v_0 = Val::from_val(env, v_0);
                    TypedFuzzInstruction::Ledger(TypedModLedger::BumpContractData(
                        FakeVal(v_0.get_payload()),
                        *v_1,
                    ))
                }
                TypedModLedgerPrototype::CreateAssetContract(v) => {
                    let v = Bytes::from_val(env, v);
                    TypedFuzzInstruction::Ledger(TypedModLedger::CreateAssetContract(v))
                }
                TypedModLedgerPrototype::CreateContract(v_0, v_1, v_2) => {
                    let v_0 = Address::from_val(env, v_0);
                    let v_1 = Bytes::from_val(env, v_1);
                    let v_2 = Bytes::from_val(env, v_2);
                    TypedFuzzInstruction::Ledger(TypedModLedger::CreateContract(v_0, v_1, v_2))
                }
                TypedModLedgerPrototype::DelContractData(v) => {
                    let v = Val::from_val(env, v);
                    TypedFuzzInstruction::Ledger(TypedModLedger::DelContractData(FakeVal(
                        v.get_payload(),
                    )))
                }
                TypedModLedgerPrototype::GetAssetContractId(v) => {
                    let v = Bytes::from_val(env, v);
                    TypedFuzzInstruction::Ledger(TypedModLedger::GetAssetContractId(v))
                }
                TypedModLedgerPrototype::GetContractData(v) => {
                    let v = Val::from_val(env, v);
                    TypedFuzzInstruction::Ledger(TypedModLedger::GetContractData(FakeVal(
                        v.get_payload(),
                    )))
                }
                TypedModLedgerPrototype::GetContractId(v_0, v_1) => {
                    let v_0 = Address::from_val(env, v_0);
                    let v_1 = Bytes::from_val(env, v_1);
                    TypedFuzzInstruction::Ledger(TypedModLedger::GetContractId(v_0, v_1))
                }
                TypedModLedgerPrototype::HasContractData(v) => {
                    let v = Val::from_val(env, v);
                    TypedFuzzInstruction::Ledger(TypedModLedger::HasContractData(FakeVal(
                        v.get_payload(),
                    )))
                }
                TypedModLedgerPrototype::PutContractData(v_0, v_1, v_2) => {
                    let v_0 = Val::from_val(env, v_0);
                    let v_1 = Val::from_val(env, v_1);
                    let v_2 = Val::from_val(env, v_2);
                    TypedFuzzInstruction::Ledger(TypedModLedger::PutContractData(
                        FakeVal(v_0.get_payload()),
                        FakeVal(v_1.get_payload()),
                        FakeVal(v_2.get_payload()),
                    ))
                }
                TypedModLedgerPrototype::UpdateCurrentContractWasm(v) => {
                    let v = Bytes::from_val(env, v);
                    TypedFuzzInstruction::Ledger(TypedModLedger::UpdateCurrentContractWasm(v))
                }
                TypedModLedgerPrototype::UploadWasm(v) => {
                    let v = Bytes::from_val(env, v);
                    TypedFuzzInstruction::Ledger(TypedModLedger::UploadWasm(v))
                }
            },
            TypedFuzzInstructionPrototype::Map(v) => match v {
                TypedModMapPrototype::MapDel(v_0, v_1) => {
                    let v_0 = Map::<Val, Val>::from_val(env, v_0);
                    let v_1 = Val::from_val(env, v_1);
                    TypedFuzzInstruction::Map(TypedModMap::MapDel(v_0, FakeVal(v_1.get_payload())))
                }
                TypedModMapPrototype::MapGet(v_0, v_1) => {
                    let v_0 = Map::<Val, Val>::from_val(env, v_0);
                    let v_1 = Val::from_val(env, v_1);
                    TypedFuzzInstruction::Map(TypedModMap::MapGet(v_0, FakeVal(v_1.get_payload())))
                }
                TypedModMapPrototype::MapHas(v_0, v_1) => {
                    let v_0 = Map::<Val, Val>::from_val(env, v_0);
                    let v_1 = Val::from_val(env, v_1);
                    TypedFuzzInstruction::Map(TypedModMap::MapHas(v_0, FakeVal(v_1.get_payload())))
                }
                TypedModMapPrototype::MapKeys(v) => {
                    let v = Map::<Val, Val>::from_val(env, v);
                    TypedFuzzInstruction::Map(TypedModMap::MapKeys(v))
                }
                TypedModMapPrototype::MapLen(v) => {
                    let v = Map::<Val, Val>::from_val(env, v);
                    TypedFuzzInstruction::Map(TypedModMap::MapLen(v))
                }
                TypedModMapPrototype::MapMaxKey(v) => {
                    let v = Map::<Val, Val>::from_val(env, v);
                    TypedFuzzInstruction::Map(TypedModMap::MapMaxKey(v))
                }
                TypedModMapPrototype::MapMinKey(v) => {
                    let v = Map::<Val, Val>::from_val(env, v);
                    TypedFuzzInstruction::Map(TypedModMap::MapMinKey(v))
                }
                TypedModMapPrototype::MapNew => TypedFuzzInstruction::Map(TypedModMap::MapNew),
                TypedModMapPrototype::MapNewFromLinearMemory(v_0, v_1, v_2) => {
                    TypedFuzzInstruction::Map(TypedModMap::MapNewFromLinearMemory(*v_0, *v_1, *v_2))
                }
                TypedModMapPrototype::MapNextKey(v_0, v_1) => {
                    let v_0 = Map::<Val, Val>::from_val(env, v_0);
                    let v_1 = Val::from_val(env, v_1);
                    TypedFuzzInstruction::Map(TypedModMap::MapNextKey(
                        v_0,
                        FakeVal(v_1.get_payload()),
                    ))
                }
                TypedModMapPrototype::MapPrevKey(v_0, v_1) => {
                    let v_0 = Map::<Val, Val>::from_val(env, v_0);
                    let v_1 = Val::from_val(env, v_1);
                    TypedFuzzInstruction::Map(TypedModMap::MapPrevKey(
                        v_0,
                        FakeVal(v_1.get_payload()),
                    ))
                }
                TypedModMapPrototype::MapPut(v_0, v_1, v_2) => {
                    let v_0 = Map::<Val, Val>::from_val(env, v_0);
                    let v_1 = Val::from_val(env, v_1);
                    let v_2 = Val::from_val(env, v_2);
                    TypedFuzzInstruction::Map(TypedModMap::MapPut(
                        v_0,
                        FakeVal(v_1.get_payload()),
                        FakeVal(v_2.get_payload()),
                    ))
                }
                TypedModMapPrototype::MapUnpackToLinearMemory(v_0, v_1, v_2, v_3) => {
                    let v_0 = Map::<Val, Val>::from_val(env, v_0);
                    TypedFuzzInstruction::Map(TypedModMap::MapUnpackToLinearMemory(
                        v_0, *v_1, *v_2, *v_3,
                    ))
                }
                TypedModMapPrototype::MapValues(v) => {
                    let v = Map::<Val, Val>::from_val(env, v);
                    TypedFuzzInstruction::Map(TypedModMap::MapValues(v))
                }
            },
            TypedFuzzInstructionPrototype::Prng(v) => match v {
                TypedModPrngPrototype::PrngBytesNew(v) => {
                    TypedFuzzInstruction::Prng(TypedModPrng::PrngBytesNew(*v))
                }
                TypedModPrngPrototype::PrngReseed(v) => {
                    let v = Bytes::from_val(env, v);
                    TypedFuzzInstruction::Prng(TypedModPrng::PrngReseed(v))
                }
                TypedModPrngPrototype::PrngU64InInclusiveRange(v_0, v_1) => {
                    TypedFuzzInstruction::Prng(TypedModPrng::PrngU64InInclusiveRange(*v_0, *v_1))
                }
                TypedModPrngPrototype::PrngVecShuffle(v) => {
                    let v = Vec::<Val>::from_val(env, v);
                    TypedFuzzInstruction::Prng(TypedModPrng::PrngVecShuffle(v))
                }
            },
            TypedFuzzInstructionPrototype::Test => TypedFuzzInstruction::Test,
            TypedFuzzInstructionPrototype::Vec(v) => match v {
                TypedModVecPrototype::VecAppend(v_0, v_1) => {
                    let v_0 = Vec::<Val>::from_val(env, v_0);
                    let v_1 = Vec::<Val>::from_val(env, v_1);
                    TypedFuzzInstruction::Vec(TypedModVec::VecAppend(v_0, v_1))
                }
                TypedModVecPrototype::VecBack(v) => {
                    let v = Vec::<Val>::from_val(env, v);
                    TypedFuzzInstruction::Vec(TypedModVec::VecBack(v))
                }
                TypedModVecPrototype::VecBinarySearch(v_0, v_1) => {
                    let v_0 = Vec::<Val>::from_val(env, v_0);
                    let v_1 = Val::from_val(env, v_1);
                    TypedFuzzInstruction::Vec(TypedModVec::VecBinarySearch(
                        v_0,
                        FakeVal(v_1.get_payload()),
                    ))
                }
                TypedModVecPrototype::VecDel(v_0, v_1) => {
                    let v_0 = Vec::<Val>::from_val(env, v_0);
                    TypedFuzzInstruction::Vec(TypedModVec::VecDel(v_0, *v_1))
                }
                TypedModVecPrototype::VecFirstIndexOf(v_0, v_1) => {
                    let v_0 = Vec::<Val>::from_val(env, v_0);
                    let v_1 = Val::from_val(env, v_1);
                    TypedFuzzInstruction::Vec(TypedModVec::VecFirstIndexOf(
                        v_0,
                        FakeVal(v_1.get_payload()),
                    ))
                }
                TypedModVecPrototype::VecFront(v) => {
                    let v = Vec::<Val>::from_val(env, v);
                    TypedFuzzInstruction::Vec(TypedModVec::VecFront(v))
                }
                TypedModVecPrototype::VecGet(v_0, v_1) => {
                    let v_0 = Vec::<Val>::from_val(env, v_0);
                    TypedFuzzInstruction::Vec(TypedModVec::VecGet(v_0, *v_1))
                }
                TypedModVecPrototype::VecInsert(v_0, v_1, v_2) => {
                    let v_0 = Vec::<Val>::from_val(env, v_0);
                    let v_2 = Val::from_val(env, v_2);
                    TypedFuzzInstruction::Vec(TypedModVec::VecInsert(
                        v_0,
                        *v_1,
                        FakeVal(v_2.get_payload()),
                    ))
                }
                TypedModVecPrototype::VecLastIndexOf(v_0, v_1) => {
                    let v_0 = Vec::<Val>::from_val(env, v_0);
                    let v_1 = Val::from_val(env, v_1);
                    TypedFuzzInstruction::Vec(TypedModVec::VecLastIndexOf(
                        v_0,
                        FakeVal(v_1.get_payload()),
                    ))
                }
                TypedModVecPrototype::VecLen(v) => {
                    let v = Vec::<Val>::from_val(env, v);
                    TypedFuzzInstruction::Vec(TypedModVec::VecLen(v))
                }
                TypedModVecPrototype::VecNew(v) => {
                    let v = Val::from_val(env, v);
                    TypedFuzzInstruction::Vec(TypedModVec::VecNew(FakeVal(v.get_payload())))
                }
                TypedModVecPrototype::VecNewFromLinearMemory(v_0, v_1) => {
                    TypedFuzzInstruction::Vec(TypedModVec::VecNewFromLinearMemory(*v_0, *v_1))
                }
                TypedModVecPrototype::VecPopBack(v) => {
                    let v = Vec::<Val>::from_val(env, v);
                    TypedFuzzInstruction::Vec(TypedModVec::VecPopBack(v))
                }
                TypedModVecPrototype::VecPopFront(v) => {
                    let v = Vec::<Val>::from_val(env, v);
                    TypedFuzzInstruction::Vec(TypedModVec::VecPopFront(v))
                }
                TypedModVecPrototype::VecPushBack(v_0, v_1) => {
                    let v_0 = Vec::<Val>::from_val(env, v_0);
                    let v_1 = Val::from_val(env, v_1);
                    TypedFuzzInstruction::Vec(TypedModVec::VecPushBack(
                        v_0,
                        FakeVal(v_1.get_payload()),
                    ))
                }
                TypedModVecPrototype::VecPushFront(v_0, v_1) => {
                    let v_0 = Vec::<Val>::from_val(env, v_0);
                    let v_1 = Val::from_val(env, v_1);
                    TypedFuzzInstruction::Vec(TypedModVec::VecPushFront(
                        v_0,
                        FakeVal(v_1.get_payload()),
                    ))
                }
                TypedModVecPrototype::VecPut(v_0, v_1, v_2) => {
                    let v_0 = Vec::<Val>::from_val(env, v_0);
                    let v_2 = Val::from_val(env, v_2);
                    TypedFuzzInstruction::Vec(TypedModVec::VecPut(
                        v_0,
                        *v_1,
                        FakeVal(v_2.get_payload()),
                    ))
                }
                TypedModVecPrototype::VecSlice(v_0, v_1, v_2) => {
                    let v_0 = Vec::<Val>::from_val(env, v_0);
                    TypedFuzzInstruction::Vec(TypedModVec::VecSlice(v_0, *v_1, *v_2))
                }
                TypedModVecPrototype::VecUnpackToLinearMemory(v_0, v_1, v_2) => {
                    let v_0 = Vec::<Val>::from_val(env, v_0);
                    TypedFuzzInstruction::Vec(TypedModVec::VecUnpackToLinearMemory(v_0, *v_1, *v_2))
                }
            },
        }
    }
}

fn main() {
    let env = Env::default();

    let contract_id = env.register_contract_wasm(None, fuzzcontract::WASM);

    let client = fuzzcontract::Client::new(&env, &contract_id);

    let mut log_to_csv = OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open("budget.csv")
        .unwrap();

    let header = "Syscalls|SyscallsInput|ArbitraryInput|CPU|MEM|Duration";
    writeln!(&mut log_to_csv, "{}", header).unwrap();

    println!("loooooooooooooooooooooooooooop");
    for _ in 0..10000 {
        env.budget().reset_unlimited();

        let mut raw_data = [0u8; 512];
        rand::thread_rng().fill(&mut raw_data[..]);

        let mut unstructured = Unstructured::new(&raw_data);

        if let Ok(input) = TypedFuzzInstructionPrototype::arbitrary(&mut unstructured) {
            println!("input: {:?}", input);

            let syscall_name = get_syscall_name_only(&input);

            let fuzz_instruction = input.to_guest(&env);
            let fuzz_instruction = FuzzInstruction::Typed(fuzz_instruction);

            let before = Instant::now();

            // Returning an error is ok; panicking is not.
            let panic_r = fuzz_catch_panic(|| {
                let _call_r = client.try_run(&fuzz_instruction);
            });
            if panic_r.is_err() {
                continue;
            }

            let after = Instant::now();
            let duration = after.duration_since(before);

            // logging
            {
                let cpu_instruction_cost = env.budget().cpu_instruction_cost();
                let memory_bytes_cost = env.budget().memory_bytes_cost();

                let log = format!(
                    "{:?}|\"{:?}\"|\"{:?}\"|{}|{}|{}",
                    syscall_name,
                    fuzz_instruction,
                    input,
                    cpu_instruction_cost,
                    memory_bytes_cost,
                    duration.as_nanos()
                );
                writeln!(&mut log_to_csv, "{}", log).unwrap();
            }
        }
    }
}

fn get_syscall_name_only(input: &TypedFuzzInstructionPrototype) -> &str {
    use TypedFuzzInstructionPrototype::*;

    match input {
        Address(v) => match v {
            TypedModAddressPrototype::AccountPublicKeyToAddress(_) => {
                "syscalls::address::account_public_key_to_address"
            }
            TypedModAddressPrototype::AddressToAccountPublicKey(_) => {
                "syscalls::address::address_to_account_public_key"
            }
            TypedModAddressPrototype::AddressToContractId(_) => {
                "syscalls::address::address_to_contract_id"
            }
            TypedModAddressPrototype::AuthorizeAsCurrContract(_) => {
                "syscalls::address::authorize_as_curr_contract"
            }
            TypedModAddressPrototype::ContractIdToAddress(_) => {
                "syscalls::address::contract_id_to_address"
            }
            TypedModAddressPrototype::RequireAuth(_) => "syscalls::address::require_auth",
            TypedModAddressPrototype::RequireAuthForArgs(_, _) => {
                "syscalls::address::require_auth_for_args"
            }
        },
        Buf(v) => match v {
            TypedModBufPrototype::BytesAppend(_, _) => "syscalls::buf::bytes_append",
            TypedModBufPrototype::BytesBack(_) => "syscalls::buf::bytes_back",
            TypedModBufPrototype::BytesCopyFromLinearMemory(_, _, _, _) => {
                "syscalls::buf::bytes_copy_from_linear_memory"
            }
            TypedModBufPrototype::BytesCopyToLinearMemory(_, _, _, _) => {
                "syscalls::buf::bytes_copy_to_linear_memory"
            }
            TypedModBufPrototype::BytesDel(_, _) => "syscalls::buf::bytes_del",
            TypedModBufPrototype::BytesFront(_) => "syscalls::buf::bytes_front",
            TypedModBufPrototype::BytesGet(_, _) => "syscalls::buf::bytes_get",
            TypedModBufPrototype::BytesInsert(_, _, _) => "syscalls::buf::bytes_insert",
            TypedModBufPrototype::BytesLen(_) => "syscalls::buf::bytes_len",
            TypedModBufPrototype::BytesNew => "syscalls::buf::bytes_new",
            TypedModBufPrototype::BytesNewFromLinearMemory(_, _) => {
                "syscalls::buf::bytes_new_from_linear_memory"
            }
            TypedModBufPrototype::BytesPop(_) => "syscalls::buf::bytes_pop",
            TypedModBufPrototype::BytesPush(_, _) => "syscalls::buf::bytes_push",
            TypedModBufPrototype::BytesPut(_, _, _) => "syscalls::buf::bytes_put",
            TypedModBufPrototype::BytesSlice(_, _, _) => "syscalls::buf::bytes_slice",
            TypedModBufPrototype::DeserializeFromBytes(_) => {
                "syscalls::buf::deserialize_from_bytes"
            }
            TypedModBufPrototype::SerializeToBytes(_) => "syscalls::buf::serialize_to_bytes",
            TypedModBufPrototype::StringCopyToLinearMemory(_, _, _, _) => {
                "syscalls::buf::string_copy_to_linear_memory"
            }
            TypedModBufPrototype::StringLen(_) => "syscalls::buf::string_len",
            TypedModBufPrototype::StringNewFromLinearMemory(_, _) => {
                "syscalls::buf::string_new_from_linear_memory"
            }
            TypedModBufPrototype::SymbolCopyToLinearMemory(_, _, _, _) => {
                "syscalls::buf::symbol_copy_to_linear_memory"
            }
            TypedModBufPrototype::SymbolIndexInLinearMemory(_, _, _) => {
                "syscalls::buf::symbol_index_in_linear_memory"
            }
            TypedModBufPrototype::SymbolLen(_) => "syscalls::buf::symbol_len",
            TypedModBufPrototype::SymbolNewFromLinearMemory(_, _) => {
                "syscalls::buf::symbol_new_from_linear_memory"
            }
        },
        Call(v) => match v {
            TypedModCallPrototype::Call(_, _, _) => "syscalls::call::call",
            TypedModCallPrototype::TryCall(_, _, _) => "syscalls::call::try_call",
        },
        Context(v) => match v {
            TypedModContextPrototype::ContractEvent(_, _) => "syscalls::context::contract_event",
            TypedModContextPrototype::FailWithError(_) => "syscalls::context::fail_with_error",
            TypedModContextPrototype::GetCurrentCallStack => {
                "syscalls::context::get_current_call_stack"
            }
            TypedModContextPrototype::GetCurrentContractAddress => {
                "syscalls::context::get_current_contract_address"
            }
            TypedModContextPrototype::GetInvokingContract => {
                "syscalls::context::get_invoking_contract"
            }
            TypedModContextPrototype::GetLedgerNetworkId => {
                "syscalls::context::get_ledger_network_id"
            }
            TypedModContextPrototype::GetLedgerSequence => "syscalls::context::get_ledger_sequence",
            TypedModContextPrototype::GetLedgerTimestamp => {
                "syscalls::context::get_ledger_timestamp"
            }
            TypedModContextPrototype::GetLedgerVersion => "syscalls::context::get_ledger_version",
            TypedModContextPrototype::LogFromLinearMemory(_, _, _, _) => {
                "syscalls::context::log_from_linear_memory"
            }
            TypedModContextPrototype::ObjCmp(_, _) => "syscalls::context::obj_cmp",
        },
        Crypto(v) => match v {
            TypedModCryptoPrototype::ComputeHashKeccak256(_) => {
                "syscalls::crypto::compute_hash_keccak256"
            }
            TypedModCryptoPrototype::ComputeHashSha256(_) => {
                "syscalls::crypto::compute_hash_sha256"
            }
            TypedModCryptoPrototype::RecoverKeyEcdsaSecp256k1(_, _, _) => {
                "syscalls::crypto::recover_key_ecdsa_secp256k1"
            }
            TypedModCryptoPrototype::VerifySigEd25519(_, _, _) => {
                "syscalls::crypto::verify_sig_ed25519"
            }
        },
        Int(v) => match v {
            TypedModIntPrototype::DurationObjFromU64(_) => "syscalls::int::duration_obj_from_u64",
            TypedModIntPrototype::DurationObjToU64(_) => "syscalls::int::duration_obj_to_u64",
            TypedModIntPrototype::I256Add(_, _) => "syscalls::int::i256_add",
            TypedModIntPrototype::I256Div(_, _) => "syscalls::int::i256_div",
            TypedModIntPrototype::I256Mul(_, _) => "syscalls::int::i256_mul",
            TypedModIntPrototype::I256ObjFromBeBytes(_) => "syscalls::int::i256_val_from_be_bytes",
            TypedModIntPrototype::I256ObjToBeBytes(_) => "syscalls::int::i256_val_to_be_bytes",
            TypedModIntPrototype::I256Pow(_, _) => "syscalls::int::i256_pow",
            TypedModIntPrototype::I256Shl(_, _) => "syscalls::int::i256_shl",
            TypedModIntPrototype::I256Shr(_, _) => "syscalls::int::i256_shr",
            TypedModIntPrototype::I256Sub(_, _) => "syscalls::int::i256_sub",
            TypedModIntPrototype::ObjFromI64(_) => "syscalls::int::obj_from_i64",
            TypedModIntPrototype::ObjFromI128Pieces(_, _) => "syscalls::int::obj_from_i128_pieces",
            TypedModIntPrototype::ObjFromI256Pieces(_, _, _, _) => {
                "syscalls::int::obj_from_i256_pieces"
            }
            TypedModIntPrototype::ObjFromU64(_) => "syscalls::int::obj_from_u64",
            TypedModIntPrototype::ObjFromU128Pieces(_, _) => "syscalls::int::obj_from_u128_pieces",
            TypedModIntPrototype::ObjFromU256Pieces(_, _, _, _) => {
                "syscalls::int::obj_from_u256_pieces"
            }
            TypedModIntPrototype::ObjToI64(_) => "syscalls::int::obj_to_i64",
            TypedModIntPrototype::ObjToI128Hi64(_) => "syscalls::int::obj_to_i128_hi64",
            TypedModIntPrototype::ObjToI128Lo64(_) => "syscalls::int::obj_to_i128_lo64",
            TypedModIntPrototype::ObjToI256HiHi(_) => "syscalls::int::obj_to_i256_hi_hi",
            TypedModIntPrototype::ObjToI256HiLo(_) => "syscalls::int::obj_to_i256_hi_lo",
            TypedModIntPrototype::ObjToI256LoHi(_) => "syscalls::int::obj_to_i256_lo_hi",
            TypedModIntPrototype::ObjToI256LoLo(_) => "syscalls::int::obj_to_i256_lo_lo",
            TypedModIntPrototype::ObjToU64(_) => "syscalls::int::obj_to_u64",
            TypedModIntPrototype::ObjToU128Hi64(_) => "syscalls::int::obj_to_u128_hi64",
            TypedModIntPrototype::ObjToU128Lo64(_) => "syscalls::int::obj_to_u128_lo64",
            TypedModIntPrototype::ObjToU256HiHi(_) => "syscalls::int::obj_to_u256_hi_hi",
            TypedModIntPrototype::ObjToU256HiLo(_) => "syscalls::int::obj_to_u256_hi_lo",
            TypedModIntPrototype::ObjToU256LoHi(_) => "syscalls::int::obj_to_u256_lo_hi",
            TypedModIntPrototype::ObjToU256LoLo(_) => "syscalls::int::obj_to_u256_lo_lo",
            TypedModIntPrototype::TimepointObjFromU64(_) => "syscalls::int::timepoint_obj_from_u64",
            TypedModIntPrototype::TimepointObjToU64(_) => "syscalls::int::timepoint_obj_to_u64",
            TypedModIntPrototype::U256Add(_, _) => "syscalls::int::u256_add",
            TypedModIntPrototype::U256Div(_, _) => "syscalls::int::u256_div",
            TypedModIntPrototype::U256Mul(_, _) => "syscalls::int::u256_mul",
            TypedModIntPrototype::U256ValFromBeBytes(_) => "syscalls::int::u256_val_from_be_bytes",
            TypedModIntPrototype::U256ValToBeBytes(_) => "syscalls::int::u256_val_to_be_bytes",
            TypedModIntPrototype::U256Pow(_, _) => "syscalls::int::u256_pow",
            TypedModIntPrototype::U256Shl(_, _) => "syscalls::int::u256_shl",
            TypedModIntPrototype::U256Shr(_, _) => "syscalls::int::u256_shr",
            TypedModIntPrototype::U256Sub(_, _) => "syscalls::int::u256_sub",
        },
        Ledger(v) => match v {
            TypedModLedgerPrototype::BumpContractData(_, _) => {
                "syscalls::ledger::bump_contract_data"
            }
            TypedModLedgerPrototype::CreateAssetContract(_) => {
                "syscalls::ledger::create_asset_contract"
            }
            TypedModLedgerPrototype::CreateContract(_, _, _) => "syscalls::ledger::create_contract",
            TypedModLedgerPrototype::DelContractData(_) => "syscalls::ledger::del_contract_data",
            TypedModLedgerPrototype::GetAssetContractId(_) => {
                "syscalls::ledger::get_asset_contract_id"
            }
            TypedModLedgerPrototype::GetContractData(_) => "syscalls::ledger::get_contract_data",
            TypedModLedgerPrototype::GetContractId(_, _) => "syscalls::ledger::get_contract_id",
            TypedModLedgerPrototype::HasContractData(_) => "syscalls::ledger::has_contract_data",
            TypedModLedgerPrototype::PutContractData(_, _, _) => {
                "syscalls::ledger::put_contract_data"
            }
            TypedModLedgerPrototype::UpdateCurrentContractWasm(_) => {
                "syscalls::ledger::update_current_contract_wasm"
            }
            TypedModLedgerPrototype::UploadWasm(_) => "syscalls::ledger::upload_wasm",
        },
        Map(v) => match v {
            TypedModMapPrototype::MapDel(_, _) => "syscalls::map::map_del",
            TypedModMapPrototype::MapGet(_, _) => "syscalls::map::map_get",
            TypedModMapPrototype::MapHas(_, _) => "syscalls::map::map_has",
            TypedModMapPrototype::MapKeys(_) => "syscalls::map::map_keys",
            TypedModMapPrototype::MapLen(_) => "syscalls::map::map_len",
            TypedModMapPrototype::MapMaxKey(_) => "syscalls::map::map_max_key",
            TypedModMapPrototype::MapMinKey(_) => "syscalls::map::map_min_key",
            TypedModMapPrototype::MapNew => "syscalls::map::map_new",
            TypedModMapPrototype::MapNewFromLinearMemory(_, _, _) => {
                "syscalls::map::map_new_from_linear_memory"
            }
            TypedModMapPrototype::MapNextKey(_, _) => "syscalls::map::map_next_key",
            TypedModMapPrototype::MapPrevKey(_, _) => "syscalls::map::map_prev_key",
            TypedModMapPrototype::MapPut(_, _, _) => "syscalls::map::map_put",
            TypedModMapPrototype::MapUnpackToLinearMemory(_, _, _, _) => {
                "syscalls::map::map_unpack_to_linear_memory"
            }
            TypedModMapPrototype::MapValues(_) => "syscalls::map::map_values",
        },
        Prng(v) => match v {
            TypedModPrngPrototype::PrngBytesNew(_) => "syscalls::prng::prng_bytes_new",
            TypedModPrngPrototype::PrngReseed(_) => "syscalls::prng::prng_reseed",
            TypedModPrngPrototype::PrngU64InInclusiveRange(_, _) => {
                "syscalls::prng::prng_u64_in_inclusive_range"
            }
            TypedModPrngPrototype::PrngVecShuffle(_) => "syscalls::prng::prng_vec_shuffle",
        },
        Test => "syscalls::test::dummy0",
        Vec(v) => match v {
            TypedModVecPrototype::VecAppend(_, _) => "syscalls::vec::vec_append",
            TypedModVecPrototype::VecBack(_) => "syscalls::vec::vec_back",
            TypedModVecPrototype::VecBinarySearch(_, _) => "syscalls::vec::vec_binary_search",
            TypedModVecPrototype::VecDel(_, _) => "syscalls::vec::vec_del",
            TypedModVecPrototype::VecFirstIndexOf(_, _) => "syscalls::vec::vec_first_index_of",
            TypedModVecPrototype::VecFront(_) => "syscalls::vec::vec_front",
            TypedModVecPrototype::VecGet(_, _) => "syscalls::vec::vec_get",
            TypedModVecPrototype::VecInsert(_, _, _) => "syscalls::vec::vec_insert",
            TypedModVecPrototype::VecLastIndexOf(_, _) => "syscalls::vec::vec_last_index_of",
            TypedModVecPrototype::VecLen(_) => "syscalls::vec::vec_len",
            TypedModVecPrototype::VecNew(_) => "syscalls::vec::vec_new",
            TypedModVecPrototype::VecNewFromLinearMemory(_, _) => {
                "syscalls::vec::vec_new_from_linear_memory"
            }
            TypedModVecPrototype::VecPopBack(_) => "syscalls::vec::vec_pop_back",
            TypedModVecPrototype::VecPopFront(_) => "syscalls::vec::vec_pop_front",
            TypedModVecPrototype::VecPushBack(_, _) => "syscalls::vec::vec_push_back",
            TypedModVecPrototype::VecPushFront(_, _) => "syscalls::vec::vec_push_front",
            TypedModVecPrototype::VecPut(_, _, _) => "syscalls::vec::vec_put",
            TypedModVecPrototype::VecSlice(_, _, _) => "syscalls::vec::vec_slice",
            TypedModVecPrototype::VecUnpackToLinearMemory(_, _, _) => {
                "syscalls::vec::vec_unpack_to_linear_memory"
            }
        },
    }
}
