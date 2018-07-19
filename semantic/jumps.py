def is_cjmp(block):
    """Verify whether the block contains conditional jump.

    Args:
        block (list): a list of instructions (dict) belonging to one block

    Returns:
        bool: does the code block contain conditional jump?
    """
    return (len(block[-1]["successors"]) == 2
            and block[-1]["instruction"].name == "set_key")


def _test_recipe(recipe, block):
    if not is_cjmp(block):
        return False
    index = 1
    recipe_index = 0

    while index <= len(block):
        if block[-index]["instruction"].name == recipe[recipe_index][0]:
            if not block[-index]["params"] == recipe[recipe_index][1]:
                break
            else:
                recipe_index += 1
                if recipe_index == len(recipe):
                    return True
        index += 1
    return False


def is_jz(block):
    if not is_cjmp(block):
        return False
    index = 1
    recipe_index = 0
    recipe = [["set_key", []],
              ["d_push_imm", [0x12345678]], ["d_shr", []],
              ["b_push_imm", [0x4]],
              ["d_push_imm", [0x40]],  # ZF
              ["d_push_imm", [block[-1]["successors"][1] + 1]],
              ["d_push_imm", [block[-1]["successors"][0] + 1]]]
    while index <= len(block):
        if block[-index]["instruction"].name == recipe[recipe_index][0]:
            if not block[-index]["params"] == recipe[recipe_index][1]:
                break
            else:
                recipe_index += 1
                if recipe_index == len(recipe):
                    return True
        index += 1
    return False


def is_jl(block):
    if not is_cjmp(block):
        return False
    index = 1
    recipe_index = 0
    recipe = [["set_key", []],
              ["d_push_imm", [0x12345678]], ["d_shr", []],
              ["b_push_imm", [0x5]],
              ["b_push_imm_zx", [0x80]], ["d_push_imm", [0x800]],  # SF, OF
              ["d_push_imm", [block[-1]["successors"][1] + 1]],
              ["d_push_imm", [block[-1]["successors"][0] + 1]]]
    while index <= len(block):
        if block[-index]["instruction"].name == recipe[recipe_index][0]:
            if not block[-index]["params"] == recipe[recipe_index][1]:
                break
            else:
                recipe_index += 1
                if recipe_index == len(recipe):
                    return True
        index += 1
    return False


def is_jp(block):
    if not is_cjmp(block):
        return False
    index = 1
    recipe_index = 0
    recipe = [["set_key", []],
              ["d_push_imm", [0x12345678]],
              ["b_push_imm_zx", [0x4]],  # PF
              ["d_push_imm", [block[-1]["successors"][1] + 1]],
              ["d_push_imm", [block[-1]["successors"][0] + 1]]]
    while index <= len(block):
        if block[-index]["instruction"].name == recipe[recipe_index][0]:
            if not block[-index]["params"] == recipe[recipe_index][1]:
                break
            else:
                recipe_index += 1
                if recipe_index == len(recipe):
                    return True
        index += 1
    return False


def is_jb(block):
    if not is_cjmp(block):
        return False
    index = 1
    recipe_index = 0
    recipe = [["set_key", []],
              ["d_push_imm", [0x12345678]],
              ["b_push_imm_zx", [0x1]],  # CF
              ["d_push_imm", [block[-1]["successors"][1] + 1]],
              ["d_push_imm", [block[-1]["successors"][0] + 1]]]
    while index <= len(block):
        if block[-index]["instruction"].name == recipe[recipe_index][0]:
            if not block[-index]["params"] == recipe[recipe_index][1]:
                break
            else:
                recipe_index += 1
                if recipe_index == len(recipe):
                    return True
        index += 1
    return False


def is_jo(block):
    if not is_cjmp(block):
        return False
    index = 1
    recipe_index = 0
    recipe = [["set_key", []],
              ["d_push_imm", [0x12345678]], ["d_shr", []],
              ["b_push_imm", [0x9]],
              ["d_push_imm", [0x800]],  # OF
              ["d_push_imm", [block[-1]["successors"][1] + 1]],
              ["d_push_imm", [block[-1]["successors"][0] + 1]]]
    while index <= len(block):
        if block[-index]["instruction"].name == recipe[recipe_index][0]:
            if not block[-index]["params"] == recipe[recipe_index][1]:
                break
            else:
                recipe_index += 1
                if recipe_index == len(recipe):
                    return True
        index += 1
    return False


def is_jle(block):
    if not is_cjmp(block):
        return False
    index = 1
    recipe_index = 0
    recipe = [["set_key", []],
              ["d_push_imm", [0x12345678]],
              ["d_push_imm", [0x800]],  # OF
              ["b_push_imm_zx", [0x80]], ["b_push_imm_zx", [0x40]],  # SF, ZF
              ["d_push_imm", [block[-1]["successors"][1] + 1]],
              ["d_push_imm", [block[-1]["successors"][0] + 1]]]
    while index <= len(block):
        if block[-index]["instruction"].name == recipe[recipe_index][0]:
            if not block[-index]["params"] == recipe[recipe_index][1]:
                break
            else:
                recipe_index += 1
                if recipe_index == len(recipe):
                    return True
        index += 1
    return False


def is_js(block):
    if not is_cjmp(block):
        return False
    index = 1
    recipe_index = 0
    recipe = [["set_key", []],
              ["d_push_imm", [0x12345678]],
              ["b_push_imm_zx", [0x80]],  # SF
              ["d_push_imm", [block[-1]["successors"][1] + 1]],
              ["d_push_imm", [block[-1]["successors"][0] + 1]]]
    while index <= len(block):
        if block[-index]["instruction"].name == recipe[recipe_index][0]:
            if not block[-index]["params"] == recipe[recipe_index][1]:
                break
            else:
                recipe_index += 1
                if recipe_index == len(recipe):
                    return True
        index += 1
    return False


def is_jbe(block):
    if not is_cjmp(block):
        return False
    index = 1
    recipe_index = 0
    recipe = [["set_key", []],
              ["d_push_imm", [0x12345678]],
              ["b_push_imm_zx", [0x40]], ["b_push_imm_zx", [0x1]],  # SF
              ["d_push_imm", [block[-1]["successors"][1] + 1]],
              ["d_push_imm", [block[-1]["successors"][0] + 1]]]
    while index <= len(block):
        if block[-index]["instruction"].name == recipe[recipe_index][0]:
            if not block[-index]["params"] == recipe[recipe_index][1]:
                break
            else:
                recipe_index += 1
                if recipe_index == len(recipe):
                    return True
        index += 1
    return False


def guess_conditional_jump(block):
    if not is_cjmp(block):
        return "JMP offset_%s;"

    if is_jle(block):
        return "JLE offset_%s; JMP offset_%s;"
    if is_jbe(block):
        return "JBE offset_%s; JMP offset_%s;"
    if is_jl(block):
        return "JL offset_%s; JMP offset_%s;"
    if is_jz(block):
        return "JZ offset_%s; JMP offset_%s;"
    if is_jb(block):
        return "JB offset_%s; JMP offset_%s;"
    if is_jo(block):
        return "JO offset_%s; JMP offset_%s;"
    if is_js(block):
        return "JS offset_%s; JMP offset_%s;"
    if is_jp(block):
        return "JP offset_%s; JMP offset_%s;"
