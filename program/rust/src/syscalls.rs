const SYSCALL_BASE: i32 = 10;

#[allow(unused)]
#[repr(i32)]
pub enum SysCalls
{
	Fail = SYSCALL_BASE,
	AssertFail,
	Print,
	Log,

	RegexCompile,
	RegexMatch,
	RegexSubst,
	RegSubHdr,
	RegexFree,

	MyName,
	SetDecision,
	Ban,
	HashData,
	Purge,
	Synth,

    ForeachField,
    FieldGet,
    FieldRetrieve,
    FieldAppend,
    FieldSet,
    FieldCopy,
    FieldUnset,

    HttpRollback,
    HttpCopy,
    HttpSetStatus,
    HttpUnsetRex,
    HttpFind
}
