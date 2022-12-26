import os
import sys

sys.path.append(os.path.dirname(os.getcwd()))

from binaryninja import *
from binaryninja.binaryview import BinaryViewType
from binaryninja.function import Function
from utils.runner import Runner
from utils.utils import get_all_files_from_path, get_matched_files_from_path

from TaintMuggle.taint_muggle import TaintMuggle

def solution(bv: BinaryViewType) -> list[Function]:
    dangerous_call = []
    # dangerous call
    # - printf
    # - fprintf
    # - vprintf, vfprintf, vsnprintf --> vfprintf
    # - sprintf, snprintf
    tm = TaintMuggle(bv)
    tm.set_source_func(['fgets', 'gets', 'scanf', 'read', 'recv'])

    tm.func_verify('printf', 0)
    tm.func_verify('fprintf', 1)
    tm.func_verify('sprintf', 1)
    tm.func_verify('snprintf', 2)
    tm.func_verify('vprintf', 0)
    tm.func_verify('vfprintf', 1)
    tm.func_verify('vsprintf', 1)
    tm.func_verify('vnsprintf', 2)
    
    tm_result = tm.get_dangerous_call()

    for func in tm_result:
        print(func.name)
    print(tm_result)
    return tm_result

    """
    #또는, 아래처럼 단순 함수 및 파라미터 검사만으로 코트 패턴 매칭 가능
    code_pattern_list = []
    function_refs = tm.get_func_refs('printf')
    for function, addr in function_refs:
        call_instr = function.get_low_level_il_at(addr).mlil
        dangerous_flag = False
        # function's param == variable, not a const
        if call_instr.params[0].operation == MediumLevelILOperation.MLIL_VAR:
            code_pattern_list.append(function)
    
    tm_result = code_pattern_list

    for func in tm_result:
        print(func.name)
    print(tm_result)
    return tm_result
    """
    