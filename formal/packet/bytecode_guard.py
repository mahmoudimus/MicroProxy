"""Trusted, fail-closed observer bridge for a restricted scalar JVM language.

No JVM timing claim: word instructions are atomic in this observer. javap and this
extractor remain trusted. Calls are recursively expanded, with no unlisted code.
"""
import re
import subprocess

MASK = (1 << 64) - 1
KERNEL_OWNER = 'io/github/mahmoudimus/quic/internal/verified/__default'
KERNEL_METHODS = {'Decode': '(JJJ)J', 'ReadPrefix': '(JJ)J', 'Unprotect': '(JJ)J'}
HEADER_OWNER = 'io/github/mahmoudimus/quic/crypto/HeaderKey'
NUMBER_OWNER = 'io/github/mahmoudimus/quic/packet/PacketNumber'
BINARY = {name: i + 2 for i, name in enumerate(
    ('ladd', 'lsub', 'lmul', 'land', 'lor', 'lxor', 'lshl', 'lushr', 'lshr',
     'iadd', 'isub', 'imul', 'iand', 'ior', 'ixor', 'ishl', 'iushr', 'ishr'))}
UNARY = {name: i + 32 for i, name in enumerate(('lneg', 'ineg', 'l2i', 'i2l', 'i2b', 'i2s', 'i2c'))}


def disassemble(javap, classes, classname):
    result = subprocess.run([str(javap), '-c', '-p', '-s', '-classpath', str(classes), classname],
                            capture_output=True, text=True, timeout=30, check=True)
    return parse(result.stdout, classname.replace('.', '/'))


def parse(text, owner):
    methods = {}
    current = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == 'static {};':
            current = '<clinit>'
            methods[current] = {'owner': owner, 'descriptor': '', 'instructions': [], 'handler': False, 'flags': {'static'}}
        elif (stripped.endswith(';') and '(' in stripped and not re.match(r'\d+:', stripped)
              and not stripped.startswith('descriptor:')):
            match = re.search(r'([\w.$]+)\([^;]*\);$', stripped)
            if not match:
                raise RuntimeError('Unrecognized javap method header')
            current = match.group(1)
            if current in methods:
                raise RuntimeError('Overloaded methods are outside the scalar policy')
            flags = set(stripped.split('(', 1)[0].split()) & {'static', 'synchronized', 'native', 'abstract'}
            methods[current] = {'owner': owner, 'descriptor': '', 'instructions': [], 'handler': False, 'flags': flags}
        elif current is not None:
            descriptor = re.match(r'descriptor:\s*(\S+)', stripped)
            instruction = re.match(r'(\d+):\s+([a-z0-9_]+)\s*(.*)', stripped)
            if descriptor:
                methods[current]['descriptor'] = descriptor.group(1)
            elif instruction:
                methods[current]['instructions'].append((int(instruction.group(1)), instruction.group(2), instruction.group(3)))
            elif stripped.startswith('Exception table:'):
                methods[current]['handler'] = True
    return methods


def signature(descriptor):
    match = re.fullmatch(r'\(([JI]*)\)([JI])', descriptor)
    if not match:
        raise RuntimeError('Only scalar int/long arguments and results are allowed')
    return match.group(1), match.group(2)


def flatten(methods, entry):
    if '<clinit>' in methods:
        raise RuntimeError('Class initializer is outside the pure scalar policy')
    if entry not in methods:
        raise RuntimeError(f'Missing scalar entry: {entry}')
    parameters, _ = signature(methods[entry]['descriptor'])
    nodes, opcodes = [], []

    def emit(kind, a=0, b=0, literal=0):
        nodes.append((kind, a, b, literal & MASK))
        return len(nodes) - 1

    arguments = [emit(1, i) for i in range(len(parameters))]

    def expand(name, args, active):
        if name in active:
            raise RuntimeError('recursive call is outside the scalar policy')
        if name not in methods:
            raise RuntimeError(f'Unlisted call target: {name}')
        method = methods[name]
        if method['flags'] & {'synchronized', 'native', 'abstract'}:
            raise RuntimeError('synchronized/native/abstract method outside scalar policy')
        if 'static' not in method['flags']:
            raise RuntimeError('Nonstatic method outside scalar policy')
        params, _ = signature(method['descriptor'])
        if len(args) != len(params) or method['handler']:
            raise RuntimeError('Invalid signature or exception handler in scalar method')
        locals_, slot = {}, 0
        for param, arg in zip(params, args):
            locals_[slot] = arg
            slot += 2 if param == 'J' else 1
        stack, returned = [], None
        if not method['instructions']:
            raise RuntimeError('Missing scalar code')
        for position, opcode, operand in method['instructions']:
            if returned is not None:
                raise RuntimeError('Instructions after scalar return')
            opcodes.append(opcode)
            load = re.fullmatch(r'[li]load(?:_(\d+))?', opcode)
            store = re.fullmatch(r'[li]store(?:_(\d+))?', opcode)
            constant = re.fullmatch(r'[li]const_(m1|\d+)', opcode)
            if load:
                index = int(load.group(1) if load.group(1) is not None else operand)
                if index not in locals_:
                    raise RuntimeError('Uninitialized local slot')
                stack.append(locals_[index])
            elif store:
                index = int(store.group(1) if store.group(1) is not None else operand)
                locals_[index] = stack.pop()
            elif constant:
                stack.append(emit(0, literal=-1 if constant.group(1) == 'm1' else int(constant.group(1))))
            elif opcode in ('bipush', 'sipush'):
                stack.append(emit(0, literal=int(operand)))
            elif opcode in ('ldc', 'ldc_w', 'ldc2_w'):
                match = re.search(r'// (?:long|int) (-?\d+)[lL]?\s*$', operand)
                if not match:
                    raise RuntimeError('Only integer literal constants are allowed')
                stack.append(emit(0, literal=int(match.group(1))))
            elif opcode in BINARY:
                b, a = stack.pop(), stack.pop()
                stack.append(emit(BINARY[opcode], a, b))
            elif opcode in UNARY:
                a = stack.pop()
                stack.append(emit(UNARY[opcode], a, a))
            elif opcode == 'invokestatic':
                match = re.search(r'// Method ([\w/$]+):(\([JI]*\)[JI])$', operand)
                if not match:
                    raise RuntimeError('Unrecognized scalar call')
                target, descriptor = match.groups()
                if '/' in target:
                    owner, target = target.rsplit('/', 1)
                    if owner != method['owner']:
                        raise RuntimeError('Unlisted external call')
                if target not in methods or descriptor != methods[target]['descriptor']:
                    raise RuntimeError('Unlisted call or signature')
                p, _ = signature(descriptor)
                call_args = [stack.pop() for _ in p][::-1]
                stack.append(expand(target, call_args, active + [name]))
            elif opcode in ('lreturn', 'ireturn'):
                returned = stack.pop()
                if stack:
                    raise RuntimeError('Nonempty scalar stack at return')
            else:
                raise RuntimeError(f'opcode outside straight-line word policy: {opcode} at {position}')
        if returned is None:
            raise RuntimeError('Missing scalar return')
        return returned

    try:
        output = expand(entry, arguments, [])
    except (ValueError, IndexError) as error:
        raise RuntimeError('Invalid scalar instruction stack/operand') from error
    return {'inputs': len(parameters), 'nodes': nodes, 'output': output, 'opcodes': opcodes}


def reference(comment, marker):
    match = re.search(r'// ' + marker + r' (\S+):(\S+)', comment)
    if not match:
        raise RuntimeError('Unrecognized symbolic member reference')
    target, descriptor = match.groups()
    owner, name = target.rsplit('.', 1) if '.' in target else ('', target)
    return owner, name, descriptor


def io_signature(descriptor):
    match = re.fullmatch(r'\((.*)\)(V|[JBIZ]|L[^;]+;)', descriptor)
    if not match:
        raise RuntimeError('Unrecognized adapter descriptor')
    parameters = re.findall(r'\[*L[^;]+;|\[*[JBIZ]', match.group(1))
    if ''.join(parameters) != match.group(1):
        raise RuntimeError('Unsupported adapter argument')
    return parameters, match.group(2)


def check_io(method, static=False, secret_parameters=()):
    """Check straight-line adapter addresses; provider sampling is an opaque call.

    Secret data may be written/returned; it cannot determine an address or branch.
    Buffer/provider implementation internals are an explicit trusted boundary.
    """
    if method['handler']:
        raise RuntimeError('Adapter exception handler outside observer policy')
    if method.get('flags', set()) & {'synchronized', 'native', 'abstract'}:
        raise RuntimeError('synchronized/native/abstract adapter outside observer policy')
    params, _ = io_signature(method['descriptor'])
    locals_, slot = ({}, 0) if static else ({0: False}, 1)
    for index, param in enumerate(params):
        locals_[slot] = index in secret_parameters
        slot += 2 if param == 'J' else 1
    stack, events, returned = [], [], False
    for position, opcode, operand in method['instructions']:
        if returned:
            raise RuntimeError('Instructions after adapter return')
        load = re.fullmatch(r'[lia]load(?:_(\d+))?', opcode)
        store = re.fullmatch(r'[lia]store(?:_(\d+))?', opcode)
        if load:
            stack.append(locals_[int(load.group(1) if load.group(1) is not None else operand)])
        elif store:
            locals_[int(store.group(1) if store.group(1) is not None else operand)] = stack.pop()
        elif re.fullmatch(r'[li]const_(m1|\d+)', opcode) or opcode in ('bipush', 'sipush'):
            stack.append(False)
        elif opcode in ('ldc', 'ldc_w', 'ldc2_w'):
            if not re.search(r'// (?:long|int) -?\d+[lL]?\s*$', operand):
                raise RuntimeError('Non-integer adapter constant')
            stack.append(False)
        elif opcode in BINARY:
            b, a = stack.pop(), stack.pop()
            stack.append(a or b)
        elif opcode in UNARY:
            pass  # Pure cast/negation preserves secrecy and stack size.
        elif opcode == 'getfield':
            owner, name, descriptor = reference(operand, 'Field')
            owner = owner or method['owner']
            if owner != HEADER_OWNER or name != 'block' or descriptor != '[B' or stack.pop():
                raise RuntimeError('Unlisted or secret adapter object identity')
            stack.append(False)
        elif opcode == 'baload':
            index, array = stack.pop(), stack.pop()
            if index or array:
                raise RuntimeError('secret array address')
            events.append('mask-read')
            stack.append(True)
        elif opcode in ('invokevirtual', 'invokestatic'):
            owner, name, descriptor = reference(operand, 'Method')
            owner = owner or method['owner']
            p, result = io_signature(descriptor)
            args = [stack.pop() for _ in p][::-1]
            receiver = False if opcode == 'invokestatic' else stack.pop()
            value = True
            if owner == 'java/nio/ByteBuffer' and (name, descriptor) in (
                    ('get', '(I)B'), ('put', '(IB)Ljava/nio/ByteBuffer;')):
                if receiver or args[0]:
                    raise RuntimeError('secret buffer address')
                events.append('buffer-read' if name == 'get' else 'buffer-write')
                value = name == 'get'  # put returns the public receiver identity.
            elif owner == KERNEL_OWNER and KERNEL_METHODS.get(name) == descriptor:
                events.append('scalar-' + name)
            elif name == 'loadSample' and owner == HEADER_OWNER and descriptor == '(Ljava/nio/ByteBuffer;I)V':
                if receiver or any(args):
                    raise RuntimeError('secret sample location')
                events.append('opaque-provider-sample')
            elif name == 'checkLength' and owner == NUMBER_OWNER and descriptor == '(I)V':
                # Public API validation has a fixed false branch on the proved
                # legal1..4 domain. Invalid-length error behavior is declassified.
                events.append('valid-domain-length-check')
            else:
                raise RuntimeError('Unlisted adapter call: ' + owner + '.' + name)
            if result != 'V':
                stack.append(value)
        elif opcode == 'pop':
            stack.pop()
        elif opcode in ('ireturn', 'lreturn', 'areturn'):
            stack.pop()
            if stack:
                raise RuntimeError('Unbalanced adapter return')
            returned = True
        else:
            raise RuntimeError(f'opcode outside fixed-address adapter policy: {opcode} at {position}')
    if not returned:
        raise RuntimeError('Missing adapter return')
    return events


def check_length_guard(method):
    """Interpret the validation path for the complete legal length interval1..4.

    Every branch must have one outcome throughout that interval; no call, write,
    allocation or unknown instruction may occur on the valid path. Error paths
    for invalid public API arguments are outside this observer.
    """
    if method['descriptor'] != '(I)V' or 'static' not in method.get('flags', set()) or method['handler']:
        raise RuntimeError('Unexpected length validator signature/handler')
    if method['flags'] & {'synchronized', 'native', 'abstract'}:
        raise RuntimeError('Unsupported length validator flags')
    code = {offset: (op, arg) for offset, op, arg in method['instructions']}
    offsets = sorted(code)
    if not offsets:
        raise RuntimeError('Missing length validator')
    pc, seen, stack, events = offsets[0], set(), [], []
    while pc in code and pc not in seen:
        seen.add(pc)
        opcode, operand = code[pc]
        following = offsets[offsets.index(pc) + 1] if pc != offsets[-1] else None
        if opcode == 'iload_0':
            stack.append((1, 4))
        elif re.fullmatch(r'iconst_[0-5]', opcode):
            n = int(opcode[-1]); stack.append((n, n))
        elif opcode in ('bipush', 'sipush'):
            n = int(operand); stack.append((n, n))
        elif opcode.startswith('if_icmp'):
            b, a = stack.pop(), stack.pop()
            conditions = {
                'if_icmplt': (a[1] < b[0], a[0] >= b[1]),
                'if_icmple': (a[1] <= b[0], a[0] > b[1]),
                'if_icmpgt': (a[0] > b[1], a[1] <= b[0]),
                'if_icmpge': (a[0] >= b[1], a[1] < b[0]),
                'if_icmpeq': (a[0] == a[1] == b[0] == b[1], a[1] < b[0] or b[1] < a[0]),
                'if_icmpne': (a[1] < b[0] or b[1] < a[0], a[0] == a[1] == b[0] == b[1])}
            if opcode not in conditions or not any(conditions[opcode]):
                raise RuntimeError('Length validator branches within legal secret domain')
            take = conditions[opcode][0]
            events.append(opcode + ('-taken' if take else '-not-taken'))
            if take:
                following = int(operand)
        elif opcode == 'goto':
            following = int(operand)
        elif opcode == 'return':
            if stack:
                raise RuntimeError('Unbalanced length validator')
            return events
        else:
            raise RuntimeError('Unlisted valid-domain validator instruction: ' + opcode)
        pc = following
    raise RuntimeError('Nonterminating/incomplete length validator')
