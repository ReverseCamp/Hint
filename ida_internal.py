# type: ignore
#
#  compiler internal functions such as __writecr8 and IDA internal function which convert from the specific assembly code
#  
#  enhanced hint and we learn ida ctree node knowledges
#  
'''
ctree AST

struct citem_t{
    ea_t ea;
    ctype_t op;
}

cinsn_t        cit_xx
cexpr_t        cot_xx
'''
import io
import idaapi
import idc
import ida_idaapi 
import ida_hexrays
from enum import IntEnum

name = f'{idaapi.idadir('plugins')}\\ida_internal.txt'

g_dict = {
    "function" : {

    },
}

__AUTHOR__ = 'bopin'
__VERSION__ = 'v0.1'

LEVEL = 0

class logable():
    def log(self,msg):
        if LEVEL:
            print(msg)

class hint_set():
    @staticmethod
    def init():
        with open(name,'r') as f:
            for result in f:
                # skip comments
                if result.startswith(';') or result == '':
                    continue
                ks = result.split(';')
                try:
                    g_dict['function'][ks[0]] = ks[1]
                except:
                    pass

class ctype_t(IntEnum):
    cot_empty    = 0,
    cot_comma    = 1,   # ///< x, y
    cot_asg      = 2,   # ///< x = y
    cot_asgbor   = 3,   # ///< x |= y
    cot_asgxor   = 4,   # ///< x ^= y
    cot_asgband  = 5,   # ///< x &= y
    cot_asgadd   = 6,   # ///< x += y
    cot_asgsub   = 7,   # ///< x -= y
    cot_asgmul   = 8,   # ///< x *= y
    cot_asgsshr  = 9,   # ///< x >>= y signed
    cot_asgushr  = 10,  # ///< x >>= y unsigned
    cot_asgshl   = 11,  # ///< x <<= y
    cot_asgsdiv  = 12,  # ///< x /= y signed
    cot_asgudiv  = 13,  # ///< x /= y unsigned
    cot_asgsmod  = 14,  # ///< x %= y signed
    cot_asgumod  = 15,  # ///< x %= y unsigned
    cot_tern     = 16,  # ///< x ? y : z
    cot_lor      = 17,  # ///< x || y
    cot_land     = 18,  # ///< x && y
    cot_bor      = 19,  # ///< x | y
    cot_xor      = 20,  # ///< x ^ y
    cot_band     = 21,  # ///< x & y
    cot_eq       = 22,  # ///< x == y int or fpu (see EXFL_FPOP)
    cot_ne       = 23,  # ///< x != y int or fpu (see EXFL_FPOP)
    cot_sge      = 24,  # ///< x >= y signed or fpu (see EXFL_FPOP)
    cot_uge      = 25,  # ///< x >= y unsigned
    cot_sle      = 26,  # ///< x <= y signed or fpu (see EXFL_FPOP)
    cot_ule      = 27,  # ///< x <= y unsigned
    cot_sgt      = 28,  # ///< x >  y signed or fpu (see EXFL_FPOP)
    cot_ugt      = 29,  # ///< x >  y unsigned
    cot_slt      = 30,  # ///< x <  y signed or fpu (see EXFL_FPOP)
    cot_ult      = 31,  # ///< x <  y unsigned
    cot_sshr     = 32,  # ///< x >> y signed
    cot_ushr     = 33,  # ///< x >> y unsigned
    cot_shl      = 34,  # ///< x << y
    cot_add      = 35,  # ///< x + y
    cot_sub      = 36,  # ///< x - y
    cot_mul      = 37,  # ///< x * y
    cot_sdiv     = 38,  # ///< x / y signed
    cot_udiv     = 39,  # ///< x / y unsigned
    cot_smod     = 40,  # ///< x % y signed
    cot_umod     = 41,  # ///< x % y unsigned
    cot_fadd     = 42,  # ///< x + y fp
    cot_fsub     = 43,  # ///< x - y fp
    cot_fmul     = 44,  # ///< x * y fp
    cot_fdiv     = 45,  # ///< x / y fp
    cot_fneg     = 46,  # ///< -x fp
    cot_neg      = 47,  # ///< -x
    cot_cast     = 48,  # ///< (type)x
    cot_lnot     = 49,  # ///< !x
    cot_bnot     = 50,  # ///< ~x
    cot_ptr      = 51,  # ///< *x, access size in 'ptrsize'
    cot_ref      = 52,  # ///< &x
    cot_postinc  = 53,  # ///< x++
    cot_postdec  = 54,  # ///< x--
    cot_preinc   = 55,  # ///< ++x
    cot_predec   = 56,  # ///< --x
    cot_call     = 57,  # ///< x(...)
    cot_idx      = 58,  # ///< x[y]
    cot_memref   = 59,  # ///< x.m
    cot_memptr   = 60,  # ///< x->m, access size in 'ptrsize'
    cot_num      = 61,  # ///< n
    cot_fnum     = 62,  # ///< fpc
    cot_str      = 63,  # ///< string constant
    cot_obj      = 64,  # ///< obj_ea
    cot_var      = 65,  # ///< v
    cot_insn     = 66,  # ///< instruction in expression, internal representation only
    cot_sizeof   = 67,  # ///< sizeof(x)
    cot_helper   = 68,  # ///< arbitrary name
    cot_type     = 69,  # ///< arbitrary type
    cot_last     = 69,
    cit_empty    = 70,  # ///< instruction types start here
    cit_block    = 71,  # ///< block-statement: { ... }
    cit_expr     = 72,  # ///< expression-statement: expr;
    cit_if       = 73,  # ///< if-statement
    cit_for      = 74,  # ///< for-statement
    cit_while    = 75,  # ///< while-statement
    cit_do       = 76,  # ///< do-statement
    cit_switch   = 77,  # ///< switch-statement
    cit_break    = 78,  # ///< break-statement
    cit_continue = 79,  # ///< continue-statement
    cit_return   = 80,  # ///< return-statement
    cit_goto     = 81,  # ///< goto-statement
    cit_asm      = 82,  # ///< asm-statement
    cit_try      = 83,  #///< new in 9.0?: try-statement
    cit_throw    = 84,  #///< new in 9.0?: throw-statement
    cit_end      = 85,

class lvar_hint_operation():
    """
    """
    def get(self,lvar):
        return 1, "!%s" % lvar.name, 1

class hint_hooks_t(ida_hexrays.Hexrays_Hooks,logable):
    """Vds create hint
    If the object under the cursor is:
    a function call;   local variable declaration
    """
    def create_hint(self, vu):
        if vu.get_current_item(ida_hexrays.USE_MOUSE):
            #
            #  ctype_t
            #
            cit = vu.item.citype
            # type
            # https://python.docs.hex-rays.com/namespaceida__hexrays.html
            # VDI_NONE,  VDI_LVAR, VDI_EXPR, VDI_FUNC, VDI_TAIL
            # cursot position at  LOCAL VAR AREA!!!
            if cit == ida_hexrays.VDI_LVAR:
                return lvar_hint_operation().get(vu.item.l)
            elif cit == ida_hexrays.VDI_EXPR:
                # citem_t,  cinsn_t , cexpr_t
                # ctype_t op
                ce :ctype_t = vu.item.e
                self.log(f'ce.obj_ea {hex(ce.obj_ea)}')
                self.log(f'ce.helper {ce.helper}')
                match ce.op:
                    case ctype_t.cot_empty:
                        self.log('cot_empty')
                    case ctype_t.cot_comma:
                        self.log('cot_comma')
                        pass
                    case ctype_t.cot_asg:
                        self.log('cot_asg')
                        pass
                    case ctype_t.cot_asgbor:
                        self.log('cot_asgbor')
                        pass
                    case ctype_t.cot_asgxor:
                        self.log('cot_asgxor')
                        pass
                    case ctype_t.cot_asgband:
                        self.log('cot_asgband')
                        pass
                    case ctype_t.cot_asgadd:
                        self.log('cot_asgadd')
                        pass
                    case ctype_t.cot_asgsub:
                        self.log('cot_asgsub')
                        pass
                    case ctype_t.cot_asgmul:
                        self.log('cot_asgmul')
                        pass
                    case ctype_t.cot_asgsshr:
                        self.log('cot_asgsshr')
                        pass
                    case ctype_t.cot_asgushr:
                        self.log('cot_asgushr')
                        pass
                    case ctype_t.cot_asgshl:
                        self.log('cot_asgshl')
                        pass
                    case ctype_t.cot_asgsdiv:
                        pass
                    case ctype_t.cot_asgudiv:
                        pass
                    case ctype_t.cot_asgsmod:
                        pass
                    case ctype_t.cot_asgumod:
                        pass
                    case ctype_t.cot_tern:
                        pass
                    case ctype_t.cot_lor:
                        pass
                    case ctype_t.cot_land:
                        pass
                    case ctype_t.cot_bor:
                        pass
                    case ctype_t.cot_xor:
                        pass
                    case ctype_t.cot_band:
                        pass
                    case ctype_t.cot_eq:
                        pass
                    case ctype_t.cot_ne:
                        pass
                    case ctype_t.cot_sge:
                        pass
                    case ctype_t.cot_uge:
                        pass
                    case ctype_t.cot_sle:
                        pass
                    case ctype_t.cot_ule:
                        pass
                    case ctype_t.cot_sgt:
                        pass
                    case ctype_t.cot_ugt:
                        pass
                    case ctype_t.cot_slt:
                        pass
                    case ctype_t.cot_ult:
                        pass
                    case ctype_t.cot_sshr:
                        pass
                    case ctype_t.cot_ushr:
                        pass
                    case ctype_t.cot_shl:
                        pass
                    case ctype_t.cot_add:
                        pass
                    case ctype_t.cot_sub:
                        pass
                    case ctype_t.cot_mul:
                        pass
                    case ctype_t.cot_sdiv:
                        pass
                    case ctype_t.cot_udiv:
                        pass
                    case ctype_t.cot_smod:
                        pass
                    case ctype_t.cot_umod:
                        pass
                    case ctype_t.cot_fadd:
                        pass
                    case ctype_t.cot_fsub:
                        pass
                    case ctype_t.cot_fmul:
                        pass
                    case ctype_t.cot_fdiv:
                        pass
                    case ctype_t.cot_fneg:
                        pass
                    case ctype_t.cot_neg:
                        pass
                    case ctype_t.cot_cast:
                        pass
                    case ctype_t.cot_lnot:
                        pass
                    case ctype_t.cot_bnot:
                        pass
                    case ctype_t.cot_ptr:
                        pass
                    case ctype_t.cot_ref:
                        pass
                    case ctype_t.cot_postinc:
                        pass
                    case ctype_t.cot_postdec:
                        pass
                    case ctype_t.cot_preinc:
                        pass
                    case ctype_t.cot_predec:
                        pass
                    case ctype_t.cot_call:
                        self.log('cot_call')
                        pass
                    case ctype_t.cot_idx:
                        pass
                    case ctype_t.cot_memref:
                        self.log('cot_memref')
                        pass
                    case ctype_t.cot_memptr:
                        self.log('cot_memptr')
                        pass
                    case ctype_t.cot_num:
                        self.log('cot_num')
                        pass
                    case ctype_t.cot_fnum:
                        self.log('cot_fnum')
                        pass
                    case ctype_t.cot_str:
                        self.log('cot_str')
                        pass
                    case ctype_t.cot_obj:
                        self.log('cot_memobj')
                        pass
                    case ctype_t.cot_var:
                        self.log('cot_memvar')
                        pass
                    case ctype_t.cot_insn:
                        pass
                    case ctype_t.cot_sizeof:
                        pass
                    case ctype_t.cot_helper:
                        self.log(f'opname: {ce.opname}  helper name: {ce.helper}')
                        if ce.helper and ce.helper in g_dict['function'].keys():
                            return 0, g_dict['function'][ce.helper],1
                        else:
                            return 0, '',1
                    case ctype_t.cot_type:
                        pass
                    case ctype_t.cit_empty:
                        self.log('cit_empty')
                        pass
                    case ctype_t.cit_block:
                        self.log('cit_block')
                        pass
                    case ctype_t.cit_expr:
                        self.log('cit_expr')
                        pass
                    case ctype_t.cit_if:
                        self.log('cit_if')
                        pass
                    case ctype_t.cit_for:
                        self.log('cit_for')
                        pass
                    case ctype_t.cit_while:
                        self.log('cit_while')
                        pass
                    case ctype_t.cit_do:
                        self.log('cit_do')
                        pass
                    case ctype_t.cit_switch:
                        self.log('cit_switch')
                        pass
                    case ctype_t.cit_break:
                        self.log('cit_break')
                        pass
                    case ctype_t.cit_continue:
                        self.log('cit_continue')
                        pass
                    case ctype_t.cit_return:
                        self.log('cit_return')
                        pass
                    case ctype_t.cit_goto:
                        self.log('cit_goto')
                        pass
                    case ctype_t.cit_asm:
                        self.log('cit_asm')
                        pass
                    case ctype_t.cit_end:
                        self.log('cit_end')
                        pass
                    case _:
                        pass
            elif cit == ida_hexrays.NONE:
                self.log('VDI_NONE')
                return 1,'VDI_NONE',1
            elif cit == ida_hexrays.FUNC:
                self.log('VDI_FUNC')
                return 1,'VDI_FUNC',1
            elif cit == ida_hexrays.TAIL:
                self.log('VDI_TAIL')
                return 1,'VDI_TAIL',1
        return 0

hint_set.init()
print('[*] hint set init finished')
vds_hooks = hint_hooks_t()
vds_hooks.hook()