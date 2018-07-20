"""This module provides tools for WProtect conditional jump
recognition.
"""


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
    """Test whether the given block contains a given subsequence. Note
    that these the verifier looks for instructions and tests whether
    they have the right parameter (this may require some redundancy in
    recipes).

    Args:
        recipe (list): a list of [instruction_name (str), [param1 (int)]]
        block (list): a list of instructions (dict) belonging to one block
    """
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
    """Verify whether the block checks for ZF, due to d_shr it matches on
    JZ only. The location is bounded by set_key and its destination
    pushes.

    Args:
        block (list): a list of instructions (dict) belonging to one block
    """
    recipe = [["set_key", []],
              ["d_push_imm", [0x12345678]], ["d_shr", []],
              ["b_push_imm", [0x4]],
              ["d_push_imm", [0x40]],  # ZF
              ["d_push_imm", [block[-1]["successors"][1] + 1]],
              ["d_push_imm", [block[-1]["successors"][0] + 1]]]
    return _test_recipe(recipe, block)


def is_jl(block):
    """Verify whether the block checks for SF and OF. The location is
    bounded by set_key and its destination pushes.

    Args:
        block (list): a list of instructions (dict) belonging to one block
    """

    recipe = [["set_key", []],
              ["d_push_imm", [0x12345678]], ["d_shr", []],
              ["b_push_imm", [0x5]],
              ["b_push_imm_zx", [0x80]], ["d_push_imm", [0x800]],  # SF, OF
              ["d_push_imm", [block[-1]["successors"][1] + 1]],
              ["d_push_imm", [block[-1]["successors"][0] + 1]]]
    return _test_recipe(recipe, block)


def is_jp(block):
    """Verify whether the block checks for PF. The location is bounded
    by set_key and its destination pushes.

    Args:
        block (list): a list of instructions (dict) belonging to one block
    """

    recipe = [["set_key", []],
              ["d_push_imm", [0x12345678]],
              ["b_push_imm_zx", [0x4]],  # PF
              ["d_push_imm", [block[-1]["successors"][1] + 1]],
              ["d_push_imm", [block[-1]["successors"][0] + 1]]]
    return _test_recipe(recipe, block)


def is_jb(block):
    """Verify whether the block checks for CF, may also match JBE.
    The location is bounded by set_key and its destination pushes.

    Args:
        block (list): a list of instructions (dict) belonging to one block
    """

    recipe = [["set_key", []],
              ["d_push_imm", [0x12345678]],
              ["b_push_imm_zx", [0x1]],  # CF
              ["d_push_imm", [block[-1]["successors"][1] + 1]],
              ["d_push_imm", [block[-1]["successors"][0] + 1]]]
    return _test_recipe(recipe, block)


def is_jo(block):
    """Verify whether the block checks for OF, may also match JLE.
    The location is bounded by set_key and its destination pushes.

    Args:
        block (list): a list of instructions (dict) belonging to one block
    """

    recipe = [["set_key", []],
              ["d_push_imm", [0x12345678]], ["d_shr", []],
              ["b_push_imm", [0x9]],
              ["d_push_imm", [0x800]],  # OF
              ["d_push_imm", [block[-1]["successors"][1] + 1]],
              ["d_push_imm", [block[-1]["successors"][0] + 1]]]
    return _test_recipe(recipe, block)


def is_jle(block):
    """Verify whether the block checks for OF, SF, and ZF.
    The location is bounded by set_key and its destination pushes.

    Args:
        block (list): a list of instructions (dict) belonging to one block
    """

    recipe = [["set_key", []],
              ["d_push_imm", [0x12345678]],
              ["d_push_imm", [0x800]],  # OF
              ["b_push_imm_zx", [0x80]], ["b_push_imm_zx", [0x40]],  # SF, ZF
              ["d_push_imm", [block[-1]["successors"][1] + 1]],
              ["d_push_imm", [block[-1]["successors"][0] + 1]]]
    return _test_recipe(recipe, block)


def is_js(block):
    """Verify whether the block checks for SF, may also match JLE.
    The location is bounded by set_key and its destination pushes.

    Args:
        block (list): a list of instructions (dict) belonging to one block
    """

    recipe = [["set_key", []],
              ["d_push_imm", [0x12345678]],
              ["b_push_imm_zx", [0x80]],  # SF
              ["d_push_imm", [block[-1]["successors"][1] + 1]],
              ["d_push_imm", [block[-1]["successors"][0] + 1]]]
    return _test_recipe(recipe, block)


def is_jbe(block):
    """Verify whether the block checks for ZF and CF.
    The location is bounded by set_key and its destination pushes.

    Args:
        block (list): a list of instructions (dict) belonging to one block
    """

    recipe = [["set_key", []],
              ["d_push_imm", [0x12345678]],
              ["b_push_imm_zx", [0x40]], ["b_push_imm_zx", [0x1]],  # ZF, CF
              ["d_push_imm", [block[-1]["successors"][1] + 1]],
              ["d_push_imm", [block[-1]["successors"][0] + 1]]]
    return _test_recipe(recipe, block)


def guess_conditional_jump(block):
    """Determine which conditional jump is in the block. An assembly
    for the corresponding conditional jump (if any) and
    a jump to the next instruction are returned.

    Args:
        block (list): a list of instructions (dict) belonging to one block
    """
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
