import os
import sys

sys.path.append(os.path.dirname(os.getcwd()))

from binaryninja import *

dangerous_flag = False


class TaintMuggle:
    def __init__(self, bv):
        self.bv = bv
        self.dangerous_call = []

    def get_func_refs(self, func_name):
        '''
        함수명을 인자로 입력받아 해당 함수가 참조되는 (함수, 주소)를 튜플 리스트로 반환

        return [(<func: x86_64@0x19be>, 6625), (<func: x86_64@0x193e>, 6496),..., (<func: x86_64@0x1a96>, 6841)]
        '''
        symbol = self.bv.symbols[func_name]
        if len(symbol) > 1:
            for sym_type in symbol:
                if sym_type.type == SymbolType.ImportedFunctionSymbol:
                    symbol = sym_type
                    break
        refs = []
        for ref in self.bv.get_code_refs(symbol.address):
            refs.append((ref.function, ref.address))
        return refs

    def get_dangerous_call(self):
        return self.dangerous_call

    def func_verify(self, func_name, param_idx):
        global dangerous_flag
        try:
            function_refs = self.get_func_refs(func_name)
            for function, addr in function_refs:
                call_instr = function.get_low_level_il_at(addr).mlil
                dangerous_flag = False
                # function's param == variable, not a const
                if call_instr.params[param_idx].operation == MediumLevelILOperation.MLIL_VAR:
                    self.taint_var(call_instr, param_idx)
                    if dangerous_flag:
                        self.dangerous_call.append(function)
                        self.taint_param(call_instr, param_idx)
        except:
                print('[!] No '+func_name)

    def set_source_func(self, func_name):
        pass

    def forward_taint(self, use_ref):
        '''
        인자로 받은 instruction문을 forward로 taint analysis 수행
        <mlil: var_20#1 = arg1#0>인 경우, var_20과 arg1에 대해 forward taint analysis 진행
        만약, 분석대상 변수가 dangerous_call에 해당하는 함수의 인자로 
        사용될 경우 위험하다고 판단하여 True 리턴, 아닐 경우 False 리턴

        [+] 분석 시, SET_VAR가 아닌 CALL인 경우에도 처리 필요 --> taint_var처럼 재귀적으로 수행 예정
        [+] dangerous_call의 경우, 인자로 전달하는게 더 나을지도...?
        '''

        trace_list = use_ref
        visited = []
        dangerous_call = ['fgets', 'gets', 'scanf', 'read', 'recv']

        while len(trace_list) > 0:
            trace_var = trace_list.pop()
            if trace_var in visited:
                return
            if trace_var.operation == MediumLevelILOperation.MLIL_SET_VAR or \
                trace_var.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA or \
                trace_var.operation == MediumLevelILOperation.MLIL_SET_VAR_ALIASED:
                var = trace_var.ssa_form.dest
                src_var = trace_var.src
                use_ref = trace_var.ssa_form.function.get_ssa_var_uses(var)
                for refs in use_ref:
                    trace_list.append(refs)
                visited.append(trace_var)
                
            elif trace_var.operation == MediumLevelILOperation.MLIL_CALL_SSA:
                func_name = self.bv.get_function_at(trace_var.dest.constant).name
                if func_name in dangerous_call:
                    return True
            elif trace_var.operation == MediumLevelILOperation.MLIL_STORE:
                if trace_var.src.operation == MediumLevelILOperation.MLIL_CONST:
                    nop = 1
                    
        return False
                

    def taint_param(self, taint_func, param_idx):
        '''
        printf(rdi_7)와 같은 taint_func 인자 전달 시, 
        해당하는 파라미터 index를 인자로 받아 taint analysis에 필요한 
        ssa_var_definition 리턴

        0x12a0(rdi_7) --> rdi_7의 ssa_var_definition인 
        rdi_7 = rax_23 반환
        '''

        if taint_func == None:
            return None
        var = taint_func.ssa_form.params[param_idx].src
        def_ref = taint_func.function.get_ssa_var_definition(var)

        return def_ref

    def get_var_from_expr(var):
        '''
        Taint Analysis 분석 시, a=b가 아닌 a=b+1인 경우,
        b+1에서 b를 반환
        '''
        if var.left.operation == MediumLevelILOperation.MLIL_VAR or \
            var.left.operation == MediumLevelILOperation.MLIL_VAR_SSA:
            var = var.left
        else:
            var = var.right
        return var

    def taint_var(self, taint_func, param_idx):
        '''
        Taint analysis를 하려는 함수와 그 함수의 파라미터를 인자로 받음
        Backward로 taint 진행하며 taint variable이 arg가 나온 경우, interprocedure하게 Backward 진행
        기본적으로 a = b인 경우를 taint 진행
        이때, backward로 진행하기 때문에 src에 대해서 taint를 하는데 src의 Operation Type이 다양하기 때문에
        이에 대한 처리 수행
            - 현재 taint variable이 SET_VAR라면? (a = b)
                - 현재 taint variable이 LOAD라면? (a = [b])
                    - [b]를 b로 변환
                - b를 구함
                - b가 ADD, SUB와 같은 expression이라면? (a = b+1 / a = b-1)
                    - get_var_from_expr() --> b만 추출
                - b가 상수라면?
                    - Taint analysis 종료 및 False 반환(위험하지 않음)
                - b가 arg라면?
                    - 몇 번재 arg인지 확인 후, 해당 함수의 ref를 찾아 재귀호출
                    - func_refs = bv.get_code_refs(trace_var.function.source_function.start)
                        - interprocedure하게 taint 해야하는 함수 리턴
                - 위의 조건에 부합하지 않다면, 계속 taint 진행
            - 현재 taint variable이 ADDRESS_OF라면? (a = &b)
                - 보통 이 경우, taint 하는 변수의 끝인 경우였음
                - a에 대해 forward taint 진행
                - b에 대해서도 forward taint 진행
                - forward taint에서 dangerous call의 인자로 쓰인 경우, 
                taint analysis 종료 및 True 반환(위험함)
            - 현재 taint variable(=instruction)이 CALL인 경우? (a = func1(num) / func2(num))
                - func1(num)이라면, func1 함수에서 num에 대해 forward로 taint analysis 수행
                - forward taint에서 dangerous call의 인자로 쓰인 경우, 
                taint analysis 종료 및 True 반환(위험함)
        '''
        #위험하면 True, 안위험하면 False
        global dangerous_flag
        def_ref = self.taint_param(taint_func, param_idx)
        taint_list = [def_ref]
        visited = []

        while len(taint_list) > 0:
            global_var_flag = False
            load_flag = False
            #print('[+] taint list = ',taint_list)
            trace_var = taint_list.pop()
            if trace_var == None:
                return False
            if trace_var in visited:
                return
            if trace_var.operation == MediumLevelILOperation.MLIL_SET_VAR or \
                trace_var.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA or \
                trace_var.operation == MediumLevelILOperation.MLIL_SET_VAR_ALIASED or \
                trace_var.operation == MediumLevelILOperation.MLIL_STORE:
                if trace_var.src.operation == MediumLevelILOperation.MLIL_LOAD_SSA:
                    trace_var = trace_var.src
                    #print('[LOAD!]', trace_var) 
                    load_flag=True
                if trace_var.src.operation == MediumLevelILOperation.MLIL_VAR or \
                    trace_var.src.operation == MediumLevelILOperation.MLIL_VAR_SSA or \
                    load_flag:
                    #taint analysis
                    var = trace_var.src.ssa_form
                    while type(var) != binaryninja.mediumlevelil.SSAVariable:
                        if var.operation == MediumLevelILOperation.MLIL_ADD or \
                            var.operation == MediumLevelILOperation.MLIL_SUB or \
                            var.operation == MediumLevelILOperation.MLIL_MUL or \
                            var.operation == MediumLevelILOperation.MLIL_DIVS:
                            var = self.get_var_from_expr(var)

                        elif var.operation == MediumLevelILOperation.MLIL_CONST_PTR or \
                            var.operation == MediumLevelILOperation.MLIL_CONST:
                            #print('may be global variable', var.constant)
                            glovar = bv.get_data_var_at(var.constant)
                            for glovar_ref in glovar.code_refs:
                                if glovar_ref.mlil.src.operation == MediumLevelILOperation.MLIL_VAR:
                                    taint_list.append(glovar_ref.mlil)
                            global_var_flag = True
                            break
                        var = var.src
                    if global_var_flag:
                        continue 
                    if 'arg' in var.name:
                        arg_num = var.name.split('arg')[1].split('#')[0]
                        func_refs = self.bv.get_code_refs(trace_var.function.source_function.start)
                        internal_refs = []
                        for ref in func_refs:
                            internal_refs.append((ref.function, ref.address))
                        for func, addr in internal_refs:
                            call_instr = func.get_low_level_il_at(addr).mlil
                            self.taint_var(call_instr, int(arg_num)-1)
                    def_ref = trace_var.ssa_form.function.get_ssa_var_definition(var)
                    taint_list.append(def_ref)
                elif trace_var.src.operation == MediumLevelILOperation.MLIL_ADDRESS_OF:
                    var = trace_var.ssa_form.dest
                    src_var = trace_var.src
                    #src taint 추가
                    while type(src_var) != binaryninja.variable.Variable:
                        src_var = src_var.src
                    src_var_name = src_var.name
                    src_ref = src_var.function.get_mlil_var_refs(src_var)
                    for s_r in src_ref:
                        src_instr = s_r.func.get_low_level_il_at(s_r.address).mlil.ssa_form
                        if src_instr.src.operation == MediumLevelILOperation.MLIL_VAR_SSA or \
                            src_instr.src.operation == MediumLevelILOperation.MLIL_VAR or \
                            src_instr.src.operation == MediumLevelILOperation.MLIL_VAR_ALIASED or \
                            src_instr.src.operation == MediumLevelILOperation.MLIL_ADDRESS_OF:
                            var_src = src_instr.src.src
                            if var_src.name == src_var_name:
                                lets_forward_taint = [src_instr]
                                if self.forward_taint(lets_forward_taint):
                                    print('!! dangerous!!')
                                    dangerous_flag = True
                                    return True
                    #print('error?', var)
                    
                    use_ref = trace_var.ssa_form.function.get_ssa_var_uses(var)
                    #print('[+] use_ref= ', use_ref, type(use_ref[0]))
                    if self.forward_taint(use_ref):
                        print('!! dangerous!!')
                        dangerous_flag = True
                        return True
                elif trace_var.operation == MediumLevelILOperation.MLIL_CONST:
                    return False
                
            elif trace_var.operation == MediumLevelILOperation.MLIL_CALL_SSA:
                call_addr = trace_var.dest.operands[0]
                call_func = self.bv.get_function_at(call_addr)
                param_list = call_func.parameter_vars
                call_taint_list = []
                for param_var in param_list:
                    for ref in call_func.get_mlil_var_refs(param_var):
                        call_taint_list.append(call_func.get_low_level_il_at(ref.address).mlil.ssa_form)

                print(call_taint_list)
                if self.forward_taint(call_taint_list):
                    dangerous_flag = True
                    return True
                
            
            visited.append(trace_var)
        return False
