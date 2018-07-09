from jinja2 import Template

from vm.obfuscation import get_bytes, strip_vm_obfuscation


def generate_reghex(vm_instructions):
    reghex = []
    for i in range(len(vm_instructions)):
        stub = get_bytes(strip_vm_obfuscation(vm_instructions[i].code))

        tmp_reghex = [[hex(ord(byte))[2:].zfill(2)
                       for byte in opcode]
                      for opcode in stub]
        tmp_reghex = [" ".join(array) for array in tmp_reghex]
        tmp_reghex = " [0-40] ".join(tmp_reghex)
        if not tmp_reghex:
            tmp_reghex = "??"
        reghex.append(tmp_reghex)
    return reghex


def generate_yara(name, strings, hexes, regexes, comment="",
                  template_file="template.yara"):
    with open(template_file, "rb") as f:
        template = Template(f.read())
        return template.render(
            name=name,
            comment=comment,
            string_detections=strings,
            hex_detections=hexes,
            re_detections=regexes
        ) + "\n"


def generate_rules(vm_instructions, filename="mnemonics.yara"):
    reghex = generate_reghex(vm_instructions)

    with open(filename, "wb") as file_handler:
        for i in range(len(reghex)):
            comment = map(str, strip_vm_obfuscation(vm_instructions[i].code))
            yara_rule = generate_yara("mnemonic_%i" % i,
                                      [], [reghex[i]], [], comment=comment)
            file_handler.write(yara_rule)
