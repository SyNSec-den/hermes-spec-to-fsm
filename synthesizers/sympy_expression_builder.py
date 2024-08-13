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

from sympy import Symbol, And, Or, Not, Equality
from sympy import simplify_logic

special_chars = ['&', '|', '!', '(', ')', '=']


def find_infix_exp(string_exp):
    vars_list = []
    enums_list = []
    e = str(string_exp).strip().replace("\n", "").replace(" ", "")
    var_name = ""
    exp_list = []
    last_operator = ""
    for i in range(len(e)):
        if e[i] not in special_chars:
            var_name += str(e[i])
            if i == len(e) - 1 and var_name != "":
                exp_list.append(var_name)
                if last_operator == "=" or last_operator == "!=":
                    enums_list.append(var_name)
                else:
                    vars_list.append(var_name)
        else:
            if var_name != "":
                exp_list.append(var_name)

                if last_operator == "=" or last_operator == "!=":
                    enums_list.append(var_name)
                else:
                    vars_list.append(var_name)

            var_name = ""
            if e[i - 1] == '!' and e[i] == '=':
                exp_list.append("!=")
                last_operator = "!="
            elif e[i] == "!" and e[i + 1] == "=":
                continue
            else:
                exp_list.append(e[i])
                last_operator = str(e[i])

    return exp_list, vars_list, enums_list


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
            stack.append(Symbol(str(postfix_exp[i])))
            continue
        else:

            if postfix_exp[i] == '&':
                try:
                    a = stack.pop()
                except:
                    a = None
                try:
                    b = stack.pop()
                except:
                    b = None

                if "coin_toss" in str(a):
                    a = None
                if "coin_toss" in str(b):
                    b = None

                if a is not None and b is not None:
                    c = And(b, a)
                    stack.append(c)
                elif a is not None:
                    stack.append(a)
                elif b is not None:
                    stack.append(b)

            elif postfix_exp[i] == '|':
                try:
                    a = stack.pop()
                except:
                    a = None
                try:
                    b = stack.pop()
                except:
                    b = None

                if "coin_toss" in str(a):
                    a = None
                if "coin_toss" in str(b):
                    b = None

                if a is not None and b is not None:
                    c = Or(b, a)
                    stack.append(c)
                elif a is not None:
                    stack.append(a)
                elif b is not None:
                    stack.append(b)
            elif postfix_exp[i] == '!':
                try:
                    a = stack.pop()
                    if "coin_toss" not in str(a):
                        c = Not(a)
                        stack.append(c)
                except IndexError:
                    pass

            elif postfix_exp[i] == '=':
                try:
                    a = stack.pop()
                    b = stack.pop()
                    if "coin_toss" not in str(a) or "coin_toss" not in str(b):
                        c = Equality(b, a)
                        stack.append(c)
                except IndexError:
                    pass
            elif postfix_exp[i] == "!=":
                try:
                    a = stack.pop()
                    b = stack.pop()
                    if "coin_toss" not in str(a) or "coin_toss" not in str(b):
                        c = Not(Equality(b, a))
                        stack.append(c)
                except IndexError:
                    pass
    if len(stack) == 0:
        return None
    return stack.pop()


def get_sympy_simplified_expression(condition_str):
    infix, vars_list, enums_list = find_infix_exp(condition_str)
    postfix = find_postfix_exp(infix)
    exp = evaluate_exp(postfix)

    if exp is None:
        return ""

    result = str(simplify_logic(exp, force=True))
    result = result.replace("~", "!")
    return result
