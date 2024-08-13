"""
This is the public release of the code of our paper titled
"Hermes: Unlocking Security Analysis of Cellular Network Protocols by Synthesizing Finite State Machines from Natural
    Language Specifications" (USENIX Security '24)
Author: Abdullah Al Ishtiaq and Syed Md Mukit Rashid
Contact: abdullah.ishtiaq@psu.edu

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from z3 import *

special_chars = ['&', '|', '!', '(', ')', '=']

get_expr_cache = {}
check_equivalence_cache = {}


def find_infix_exp(string_exp):
    ee = str(string_exp).strip().replace("\n", "").replace(" ", "")
    var_name = ""
    exp_list = []
    for i in range(len(ee)):
        if ee[i] not in special_chars:
            var_name += str(ee[i])
            if i == len(ee) - 1 and var_name != "":
                exp_list.append(var_name)
        else:
            if var_name != "":
                exp_list.append(var_name)
            var_name = ""
            if ee[i - 1] == '!' and ee[i] == '=':
                exp_list.append("!=")
            elif ee[i] == "!" and ee[i + 1] == "=":
                continue
            else:
                exp_list.append(ee[i])

    return exp_list


def find_postfix_exp(infix_exp):
    stack = []
    operators = ['&', '|', '!=', '!', '(', ')', '=']
    precedence = {'!': 1, '!=': 2, '=': 2, '&': 3, '|': 4}
    postfix_exp = []
    for i in range(len(infix_exp)):
        if infix_exp[i] not in operators:
            postfix_exp.append(infix_exp[i])
            continue

        if infix_exp[i] == '(':
            stack.append(infix_exp[i])
            continue

        if infix_exp[i] == ')':
            while len(stack) != 0 and stack[-1] != '(':
                postfix_exp.append(stack.pop())
            stack.pop()
            continue

        if infix_exp[i] in operators:
            if len(stack) == 0 or stack[-1] == '(':
                stack.append(infix_exp[i])
            else:
                while len(stack) != 0 and stack[-1] != '(' and precedence[infix_exp[i]] >= precedence[stack[-1]]:
                    postfix_exp.append(stack.pop())
                stack.append(infix_exp[i])

    while len(stack) != 0:
        postfix_exp.append(stack.pop())

    return postfix_exp


def evaluate_exp(postfix_exp):
    operators = ['&', '|', '!=', '!', '(', ')', '=']
    stack = []
    for i in range(len(postfix_exp)):
        if postfix_exp[i] not in operators:
            stack.append(Bool(str(postfix_exp[i])))
            continue
        else:
            if postfix_exp[i] == '&':
                a = stack.pop()
                b = stack.pop()
                c = And(b, a)
                stack.append(c)

            elif postfix_exp[i] == '|':
                a = stack.pop()
                b = stack.pop()
                c = Or(b, a)
                stack.append(c)

            elif postfix_exp[i] == '!':
                a = stack.pop()
                c = Not(a)
                stack.append(c)

            elif postfix_exp[i] == '=':
                a = stack.pop()
                b = stack.pop()
                c = Not(Xor(b, a))
                stack.append(c)

            elif postfix_exp[i] == "!=":
                a = stack.pop()
                b = stack.pop()
                c = Xor(b, a)
                stack.append(c)

    return stack.pop()


def get_expr(text: str):
    global get_expr_cache
    if text in get_expr_cache:
        return get_expr_cache[text]
    else:
        expr = evaluate_exp(find_postfix_exp(find_infix_exp(text)))
        get_expr_cache[text] = expr
        return expr


def check_equivalence(string_1, string_2):
    global check_equivalence_cache
    string_1 = string_1.replace("<PRIMARY>", "").replace("</PRIMARY>", "").strip()
    string_2 = string_2.replace("<PRIMARY>", "").replace("</PRIMARY>", "").strip()

    if string_1 == string_2:
        return True
    elif string_1 == "" or string_2 == "":
        return False

    if string_1 in check_equivalence_cache and string_2 in check_equivalence_cache[string_1]:
        check_equivalence_cache[string_2][string_1] = check_equivalence_cache[string_1][string_2]
        return check_equivalence_cache[string_1][string_2]
    elif string_2 in check_equivalence_cache and string_1 in check_equivalence_cache[string_2]:
        check_equivalence_cache[string_1][string_2] = check_equivalence_cache[string_2][string_1]
        return check_equivalence_cache[string_2][string_1]

    if string_1 not in check_equivalence_cache:
        check_equivalence_cache[string_1] = {}
    if string_2 not in check_equivalence_cache:
        check_equivalence_cache[string_2] = {}

    db_result = ""
    if db_result == "TRUE":
        check_equivalence_cache[string_1][string_2] = True
        check_equivalence_cache[string_2][string_1] = True
        return True
    elif db_result == "FALSE":
        check_equivalence_cache[string_1][string_2] = False
        check_equivalence_cache[string_2][string_1] = False
        return False

    try:
        expr1 = get_expr(string_1)
        expr2 = get_expr(string_2)

        c = Xor(expr1, expr2)
        s = Solver()
        s.add(c)
        if s.check() == z3.unsat:
            check_equivalence_cache[string_1][string_2] = True
            check_equivalence_cache[string_2][string_1] = True
            return True
        else:
            check_equivalence_cache[string_1][string_2] = False
            check_equivalence_cache[string_2][string_1] = False
            return False
    except KeyboardInterrupt:
        print("KeyboardInterrupt")
        sys.exit()
    except:
        print("ERROR:")
        print("string_1 :", string_1)
        print("string_2 :", string_2)
        print()
        check_equivalence_cache[string_1][string_2] = False
        check_equivalence_cache[string_2][string_1] = False
        return False


def check_entail(string_1, string_2):
    string_1 = string_1.replace("<PRIMARY>", "").replace("</PRIMARY>", "").strip()
    string_2 = string_2.replace("<PRIMARY>", "").replace("</PRIMARY>", "").strip()

    string_3 = "(" + string_1 + ") & !(" + string_2 + ")"
    result = check_equivalence(string_3 + " | " + string_2, string_1)
    return result

