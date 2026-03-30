from __future__ import annotations

import argparse
import os
import time
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import pyghidra


CHUNK_SIZE = 1024 * 1024
BYTES_PER_LINE = 16
MIN_STRING_LENGTH = 4
DEFAULT_EXPORT_SUFFIX = '_ghidra_export'
IMPORT_LIKE_SEGMENTS = {
    'extern', '.idata', 'idata', '.idata$2', '.idata$4', '.idata$5', '.idata$6',
    '.got', 'got', '.got.plt', 'got.plt', '__la_symbol_ptr', '__nl_symbol_ptr',
}
RAW_POINTER_SEGMENT_PREFIXES = ('.data', '.rdata', 'data')
NOISY_SEGMENT_PREFIXES = ('.debug', 'debug')
NOISY_SEGMENT_NAMES = {'headers', 'tdb', '.reloc', 'reloc'}


@dataclass
class ExportSummary:
    export_dir: Path
    total_functions: int = 0
    exported_functions: int = 0
    skipped_functions: int = 0
    failed_functions: int = 0
    string_count: int = 0
    import_count: int = 0
    export_count: int = 0
    pointer_count: int = 0
    memory_file_count: int = 0
    memory_total_bytes: int = 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Export reverse-engineering context for AI with pyghidra.'
    )
    parser.add_argument('binary', help='Path to the executable or library file to analyze.')
    parser.add_argument(
        'export_dir',
        nargs='?',
        help='Optional export directory path. Defaults to <binary_name>_ghidra_export.',
    )
    return parser


def resolve_export_dir(binary_path: Path, export_dir_arg: str | None) -> Path:
    if export_dir_arg is None:
        return (binary_path.parent / f'{binary_path.name}{DEFAULT_EXPORT_SUFFIX}').resolve()
    return Path(export_dir_arg).expanduser().resolve()


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8', newline='\n') as handle:
        handle.write(content)


def iter_java_iterator(iterator) -> Iterable:
    while iterator.hasNext():
        yield iterator.next()


def iter_java_collection(collection) -> Iterable:
    iterator = collection.iterator()
    while iterator.hasNext():
        yield iterator.next()


def to_address(program, offset: int):
    return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)


def address_offset(address) -> int:
    return int(address.getOffset())


def safe_text(value) -> str:
    if value is None:
        return ''
    text = str(value).replace('\r', ' ').replace('\n', ' ').replace('|', '/').strip()
    return text[:77] + '...' if len(text) > 80 else text


def format_address_list(addresses: list[int]) -> str:
    return 'none' if not addresses else ', '.join(hex(address) for address in addresses)


def make_project_name(binary_path: Path) -> str:
    stem = ''.join(ch if ch.isalnum() else '_' for ch in binary_path.stem)
    return f'{stem}_{os.getpid()}_{int(time.time())}'


def block_name_lower(name: str | None) -> str:
    return '' if not name else name.lower()


def should_export_block_name(name: str | None) -> bool:
    lower_name = block_name_lower(name)
    if not lower_name:
        return False
    if lower_name in NOISY_SEGMENT_NAMES:
        return False
    return not any(lower_name.startswith(prefix) for prefix in NOISY_SEGMENT_PREFIXES)


def get_block_name(program, address) -> str:
    block = program.getMemory().getBlock(address)
    if block is not None:
        name = block.getName()
        return name if name else 'unknown'
    if address.getAddressSpace().isExternalSpace():
        return 'extern'
    return 'unknown'


def should_export_address(program, address) -> bool:
    if address is None or address.getAddressSpace().isExternalSpace():
        return False
    return should_export_block_name(get_block_name(program, address))


def decompile_function(flat_api, function) -> str:
    from ghidra.app.decompiler.flatapi import FlatDecompilerAPI

    decompiler = FlatDecompilerAPI(flat_api)
    try:
        return str(decompiler.decompile(function))
    finally:
        decompiler.dispose()


def function_entry_offset(function) -> int:
    return address_offset(function.getEntryPoint())


def is_library_like_function(function) -> bool:
    if function.isExternal():
        return True
    try:
        if function.isThunk():
            thunked = function.getThunkedFunction(True)
            if thunked is not None and thunked.isExternal():
                return True
    except Exception:
        pass
    return False


def get_callers(function) -> list[int]:
    monitor = pyghidra.task_monitor()
    callers = set()
    try:
        for caller in iter_java_collection(function.getCallingFunctions(monitor)):
            if caller is None or caller.isExternal():
                continue
            callers.add(function_entry_offset(caller))
    except Exception:
        return []
    return sorted(callers)


def get_callees(function) -> list[int]:
    monitor = pyghidra.task_monitor()
    callees = set()
    try:
        for callee in iter_java_collection(function.getCalledFunctions(monitor)):
            if callee is None or callee.isExternal():
                continue
            callees.add(function_entry_offset(callee))
    except Exception:
        return []
    return sorted(callees)


def export_decompiled_functions(flat_api, program, export_dir: Path, summary: ExportSummary) -> None:
    decompile_dir = export_dir / 'decompile'
    ensure_dir(decompile_dir)
    failed_funcs: list[tuple[int, str, str]] = []
    skipped_funcs: list[tuple[int, str, str]] = []
    function_index: list[dict[str, object]] = []
    addr_to_info: dict[int, dict[str, object]] = {}
    name_cache: dict[int, str] = {}

    for function in iter_java_iterator(program.getListing().getFunctions(True)):
        summary.total_functions += 1
        func_ea = function_entry_offset(function)
        func_name = function.getName()
        name_cache[func_ea] = func_name
        if function.getBody().isEmpty():
            skipped_funcs.append((func_ea, func_name, 'not a valid function'))
            summary.skipped_functions += 1
            continue
        if is_library_like_function(function):
            skipped_funcs.append((func_ea, func_name, 'library function'))
            summary.skipped_functions += 1
            continue
        try:
            dec_str = decompile_function(flat_api, function).rstrip()
            if not dec_str:
                failed_funcs.append((func_ea, func_name, 'empty decompilation result'))
                summary.failed_functions += 1
                continue
            callers = get_callers(function)
            callees = get_callees(function)
            output_filename = f'{func_ea:X}.c'
            write_text(
                decompile_dir / output_filename,
                '\n'.join([
                    '/*',
                    f' * func-name: {func_name}',
                    f' * func-address: {hex(func_ea)}',
                    f' * callers: {format_address_list(callers)}',
                    f' * callees: {format_address_list(callees)}',
                    ' */',
                    '',
                    dec_str,
                    '',
                ]),
            )
            info = {
                'address': func_ea,
                'name': func_name,
                'filename': output_filename,
                'callers': callers,
                'callees': callees,
            }
            function_index.append(info)
            addr_to_info[func_ea] = info
            summary.exported_functions += 1
            if summary.exported_functions % 100 == 0:
                print(f'[+] Exported {summary.exported_functions} / {summary.total_functions} functions...')
        except Exception as exc:
            failed_funcs.append((func_ea, func_name, f'unexpected error: {exc}'))
            summary.failed_functions += 1

    if failed_funcs:
        lines = [
            f'# Failed to decompile {len(failed_funcs)} functions',
            '# Format: address | function_name | reason',
            '#' + '=' * 80,
            '',
        ]
        lines.extend(f'{hex(addr)} | {name} | {reason}' for addr, name, reason in failed_funcs)
        write_text(export_dir / 'decompile_failed.txt', '\n'.join(lines) + '\n')
    if skipped_funcs:
        lines = [
            f'# Skipped {len(skipped_funcs)} functions',
            '# Format: address | function_name | reason',
            '#' + '=' * 80,
            '',
        ]
        lines.extend(f'{hex(addr)} | {name} | {reason}' for addr, name, reason in skipped_funcs)
        write_text(export_dir / 'decompile_skipped.txt', '\n'.join(lines) + '\n')
    if function_index:
        lines = [
            '# Function Index',
            f'# Total exported functions: {len(function_index)}',
            '#' + '=' * 80,
            '',
        ]
        for info in function_index:
            address = int(info['address'])
            callers = list(info['callers'])
            callees = list(info['callees'])
            lines.extend([
                '=' * 80,
                f'Function: {info["name"]}',
                f'Address: {hex(address)}',
                f'File: {info["filename"]}',
                '',
            ])
            if callers:
                lines.append(f'Called by ({len(callers)} callers):')
                for caller_addr in callers:
                    caller_info = addr_to_info.get(caller_addr)
                    if caller_info is None:
                        lines.append(f'  - {hex(caller_addr)} ({name_cache.get(caller_addr, "unknown")})')
                    else:
                        lines.append(
                            f'  - {hex(caller_addr)} ({caller_info["name"]}) -> {caller_info["filename"]}'
                        )
            else:
                lines.append('Called by: none')
            lines.append('')
            if callees:
                lines.append(f'Calls ({len(callees)} callees):')
                for callee_addr in callees:
                    callee_info = addr_to_info.get(callee_addr)
                    if callee_info is None:
                        lines.append(f'  - {hex(callee_addr)} ({name_cache.get(callee_addr, "unknown")})')
                    else:
                        lines.append(
                            f'  - {hex(callee_addr)} ({callee_info["name"]}) -> {callee_info["filename"]}'
                        )
            else:
                lines.append('Calls: none')
            lines.append('')
        write_text(export_dir / 'function_index.txt', '\n'.join(lines) + '\n')

    print('[*] Decompilation Summary:')
    print(f'    Total functions: {summary.total_functions}')
    print(f'    Exported: {summary.exported_functions}')
    print(f'    Skipped: {summary.skipped_functions} (library/invalid functions)')
    print(f'    Failed: {summary.failed_functions}')


def classify_string_type(string_instance) -> str:
    charset = str(string_instance.getCharsetName()).upper()
    if 'UTF-32' in charset or 'UTF32' in charset:
        return 'UTF-32'
    if 'UTF-16' in charset or 'UTF16' in charset:
        return 'UTF-16'
    return 'ASCII'


def export_strings(program, export_dir: Path, summary: ExportSummary) -> None:
    from ghidra.program.model.data import StringDataInstance
    from ghidra.program.util import DefinedStringIterator

    lines = [
        '# Strings exported from IDA',
        '# Format: address | length | type | string',
        '#' + '=' * 80,
        '',
    ]
    iterator = DefinedStringIterator.forProgram(program)
    while iterator.hasNext():
        data = iterator.next()
        try:
            if not should_export_address(program, data.getAddress()):
                continue
            string_instance = StringDataInstance.getStringDataInstance(data)
            value = string_instance.getStringValue()
            if value is None or data.getLength() < MIN_STRING_LENGTH:
                continue
            lines.append(
                f'{hex(address_offset(data.getAddress()))} | {data.getLength()} | '
                f'{classify_string_type(string_instance)} | '
                f'{str(value).replace(chr(10), "\\n").replace(chr(13), "\\r")}'
            )
            summary.string_count += 1
        except Exception:
            continue
    write_text(export_dir / 'strings.txt', '\n'.join(lines) + '\n')
    print('[*] Strings Summary:')
    print(f'    Total strings exported: {summary.string_count}')


def collect_pe_imports(program, binary_path: Path) -> list[tuple[int, str]]:
    from ghidra.app.util.bin import RandomAccessByteProvider
    from ghidra.app.util.bin.format.pe import PortableExecutable
    from java.io import File

    imports: list[tuple[int, str]] = []
    image_base = address_offset(program.getImageBase())
    provider = RandomAccessByteProvider(File(str(binary_path)))
    try:
        pe = PortableExecutable(provider, PortableExecutable.SectionLayout.FILE, True, False)
        for entry in pe.getNTHeader().getOptionalHeader().getDataDirectories():
            if entry is None or entry.getClass().getSimpleName() != 'ImportDataDirectory':
                continue
            for info in entry.getImports():
                imports.append((image_base + int(info.getAddress()), info.getName() or 'unknown'))
    finally:
        provider.close()
    return imports


def collect_pe_exports(program, binary_path: Path) -> list[tuple[int, str]]:
    from ghidra.app.util.bin import RandomAccessByteProvider
    from ghidra.app.util.bin.format.pe import PortableExecutable
    from java.io import File

    exports: list[tuple[int, str]] = []
    image_base = address_offset(program.getImageBase())
    provider = RandomAccessByteProvider(File(str(binary_path)))
    try:
        pe = PortableExecutable(provider, PortableExecutable.SectionLayout.FILE, True, False)
        for entry in pe.getNTHeader().getOptionalHeader().getDataDirectories():
            if entry is None or entry.getClass().getSimpleName() != 'ExportDataDirectory':
                continue
            for info in entry.getExports():
                name = info.getName() or f'ordinal_{info.getOrdinal()}'
                exports.append((image_base + int(info.getAddress()), name))
    finally:
        provider.close()
    return exports


def collect_generic_imports(program) -> list[tuple[int, str]]:
    imports: list[tuple[int, str]] = []
    iterator = program.getSymbolTable().getExternalSymbols()
    while iterator.hasNext():
        symbol = iterator.next()
        imports.append((address_offset(symbol.getAddress()), symbol.getName(True)))
    return imports


def collect_generic_exports(program) -> list[tuple[int, str]]:
    exports: list[tuple[int, str]] = []
    symbol_table = program.getSymbolTable()
    iterator = symbol_table.getExternalEntryPointIterator()
    while iterator.hasNext():
        address = iterator.next()
        symbol = symbol_table.getPrimarySymbol(address)
        if symbol is not None:
            exports.append((address_offset(address), symbol.getName(True)))
    return exports


def normalize_entry_export_name(name: str, program, address) -> str:
    lower_name = name.lower()
    if lower_name == 'entry':
        function = program.getFunctionManager().getFunctionAt(address)
        return function.getName() if function is not None else name
    if lower_name.startswith('tls_callback_'):
        return 'TlsCallback_' + name.split('_')[-1]
    return name


def collect_entry_like_exports(program) -> list[tuple[int, str]]:
    exports: list[tuple[int, str]] = []
    iterator = program.getSymbolTable().getSymbolIterator(True)
    while iterator.hasNext():
        symbol = iterator.next()
        try:
            if not symbol.isExternalEntryPoint():
                continue
        except Exception:
            continue
        name = symbol.getName(True)
        lower_name = name.lower()
        if lower_name != 'entry' and not lower_name.startswith('tls_callback_'):
            continue
        exports.append((address_offset(symbol.getAddress()), normalize_entry_export_name(name, program, symbol.getAddress())))
    return exports


def export_imports(program, binary_path: Path, export_dir: Path, summary: ExportSummary) -> None:
    imports = collect_pe_imports(program, binary_path) if program.getExecutableFormat() == 'Portable Executable (PE)' else collect_generic_imports(program)
    lines = ['# Imports', '# Format: func-addr:func-name', '#' + '=' * 60, '']
    for addr, name in sorted(set(imports), key=lambda item: (item[0], item[1])):
        lines.append(f'{hex(addr)}:{name}')
        summary.import_count += 1
    write_text(export_dir / 'imports.txt', '\n'.join(lines) + '\n')
    print('[*] Imports Summary:')
    print(f'    Total imports exported: {summary.import_count}')


def export_exports(program, binary_path: Path, export_dir: Path, summary: ExportSummary) -> None:
    exports = collect_pe_exports(program, binary_path) if program.getExecutableFormat() == 'Portable Executable (PE)' else collect_generic_exports(program)
    exports.extend(collect_entry_like_exports(program))
    lines = ['# Exports', '# Format: func-addr:func-name', '#' + '=' * 60, '']
    for addr, name in sorted(set(exports), key=lambda item: (item[0], item[1])):
        lines.append(f'{hex(addr)}:{name}')
        summary.export_count += 1
    write_text(export_dir / 'exports.txt', '\n'.join(lines) + '\n')
    print('[*] Exports Summary:')
    print(f'    Total exports exported: {summary.export_count}')


def read_memory_bytes(program, start_offset: int, count: int) -> list[int]:
    memory = program.getMemory()
    start_address = to_address(program, start_offset)
    values: list[int] = []
    for index in range(count):
        try:
            values.append(int(memory.getByte(start_address.add(index))) & 0xFF)
        except Exception:
            values.append(0)
    return values


def build_hex_ascii_line(line_bytes: list[int]) -> tuple[str, str]:
    hex_part = ''
    for index, value in enumerate(line_bytes):
        hex_part += f'{value:02X} '
        if index == 7:
            hex_part += ' '
    remaining = BYTES_PER_LINE - len(line_bytes)
    if remaining > 0:
        if len(line_bytes) <= 8:
            hex_part += ' '
        hex_part += '   ' * remaining
    ascii_part = ''.join(chr(value) if 0x20 <= value <= 0x7E else '.' for value in line_bytes)
    return hex_part.ljust(49), ascii_part


def export_memory(program, export_dir: Path, summary: ExportSummary) -> None:
    memory_dir = export_dir / 'memory'
    ensure_dir(memory_dir)
    for block in program.getMemory().getBlocks():
        segment_name = block.getName()
        if not should_export_block_name(segment_name):
            continue
        block_start = address_offset(block.getStart())
        block_end = address_offset(block.getEnd()) + 1
        print(f'[*] Processing segment: {segment_name} ({hex(block_start)} - {hex(block_end)})')
        current_offset = block_start
        while current_offset < block_end:
            chunk_end = min(current_offset + CHUNK_SIZE, block_end)
            output_path = memory_dir / f'{current_offset:08X}--{chunk_end:08X}.txt'
            lines = [
                f'# Memory dump: {hex(current_offset)} - {hex(chunk_end)}',
                f'# Segment: {segment_name}',
                '#' + '=' * 76,
                '',
                '# Address        | Hex Bytes                                       | ASCII',
                '#' + '-' * 76,
            ]
            line_offset = current_offset
            while line_offset < chunk_end:
                line_size = min(BYTES_PER_LINE, chunk_end - line_offset)
                line_bytes = read_memory_bytes(program, line_offset, line_size)
                hex_part, ascii_part = build_hex_ascii_line(line_bytes)
                lines.append(f'{line_offset:016X} | {hex_part} | {ascii_part}')
                summary.memory_total_bytes += len(line_bytes)
                line_offset += BYTES_PER_LINE
            write_text(output_path, '\n'.join(lines) + '\n')
            summary.memory_file_count += 1
            current_offset = chunk_end
    print('')
    print('[*] Memory Export Summary:')
    print(
        f'    Total bytes exported: {summary.memory_total_bytes} '
        f'({summary.memory_total_bytes / (1024 * 1024):.2f} MB)'
    )
    print(f'    Files created: {summary.memory_file_count}')


def is_valid_target(program, address) -> bool:
    if address is None:
        return False
    if address.getAddressSpace().isExternalSpace():
        return True
    return program.getMemory().contains(address)


def get_target_name(program, target_address) -> str:
    symbol = program.getSymbolTable().getPrimarySymbol(target_address)
    if symbol is not None:
        return safe_text(symbol.getName(True))
    function = program.getFunctionManager().getFunctionContaining(target_address)
    if function is not None:
        return safe_text(function.getName())
    return 'unknown'


def try_get_string_preview(program, target_address) -> str:
    from ghidra.program.model.data import StringDataInstance

    if not should_export_address(program, target_address):
        return ''
    data = program.getListing().getDefinedDataContaining(target_address)
    if data is None or not StringDataInstance.isString(data):
        return ''
    string_instance = StringDataInstance.getStringDataInstance(data)
    if string_instance is None:
        return ''
    if target_address != data.getAddress():
        offset = address_offset(target_address) - address_offset(data.getAddress())
        try:
            string_instance = string_instance.getByteOffcut(offset)
        except Exception:
            return ''
    value = string_instance.getStringValue()
    return 'string_literal' if not value else f'"{safe_text(value)}"'


def is_import_target(program, target_address, target_name: str) -> bool:
    lower_name = target_name.lower()
    if lower_name.startswith('__imp_') or lower_name.startswith('imp_'):
        return True
    return block_name_lower(get_block_name(program, target_address)) in IMPORT_LIKE_SEGMENTS


def classify_pointer_target(program, target_address) -> tuple[str, str, str]:
    target_name = get_target_name(program, target_address)
    if is_import_target(program, target_address, target_name):
        return target_name, 'import_pointer', 'import_entry'
    string_preview = try_get_string_preview(program, target_address)
    if string_preview:
        return target_name, 'string_pointer', string_preview
    function_at = program.getFunctionManager().getFunctionAt(target_address)
    if function_at is not None:
        return target_name, 'function_pointer', 'function_start'
    function_containing = program.getFunctionManager().getFunctionContaining(target_address)
    if function_containing is not None:
        return target_name, 'code_pointer', f'inside_{safe_text(function_containing.getName())}'
    if program.getListing().getInstructionContaining(target_address) is not None:
        return target_name, 'code_pointer', 'instruction'
    data = program.getListing().getDefinedDataContaining(target_address)
    if data is not None:
        data_type_name = ''
        try:
            data_type_name = data.getDataType().getName().lower()
        except Exception:
            pass
        if 'struct' in data_type_name or 'structure' in data_type_name:
            return target_name, 'struct_pointer', 'struct_data'
        return target_name, 'data_pointer', f'data_item_size={data.getLength()}'
    return target_name, 'unknown_pointer', ''


def add_pointer_record(records, seen, program, source_address, target_address) -> None:
    source_offset = address_offset(source_address)
    target_offset = address_offset(target_address)
    key = (source_offset, target_offset)
    if key in seen:
        return
    seen.add(key)
    target_name, target_type, target_detail = classify_pointer_target(program, target_address)
    records.append(
        {
            'source_addr': source_offset,
            'source_seg': get_block_name(program, source_address),
            'points_to': target_offset,
            'target_name': target_name,
            'target_type': target_type,
            'target_detail': target_detail,
        }
    )


def collect_data_xrefs(program, records, seen) -> int:
    reference_manager = program.getReferenceManager()
    address_set = program.getMemory().getLoadedAndInitializedAddressSet()
    total = 0
    for source_address in iter_java_iterator(reference_manager.getReferenceSourceIterator(address_set, True)):
        if not should_export_address(program, source_address):
            continue
        try:
            references = reference_manager.getReferencesFrom(source_address)
        except Exception:
            continue
        for reference in references:
            try:
                if not reference.getReferenceType().isData():
                    continue
            except Exception:
                continue
            target_address = reference.getToAddress()
            if is_valid_target(program, target_address):
                add_pointer_record(records, seen, program, source_address, target_address)
                total += 1
    return total


def read_pointer_value(program, source_address, pointer_size: int) -> int:
    raw = bytes(read_memory_bytes(program, address_offset(source_address), pointer_size))
    byteorder = 'big' if program.getMemory().isBigEndian() else 'little'
    return int.from_bytes(raw, byteorder=byteorder, signed=False)


def try_make_pointer_address(program, value: int):
    try:
        return to_address(program, value)
    except Exception:
        return None


def collect_raw_pointers(program, records, seen) -> int:
    pointer_size = program.getDefaultPointerSize()
    total = 0
    for block in program.getMemory().getBlocks():
        segment_name = block.getName()
        lower_name = block_name_lower(segment_name)
        if not should_export_block_name(segment_name):
            continue
        if not lower_name.startswith(RAW_POINTER_SEGMENT_PREFIXES):
            continue
        print(f'[*] Scanning segment: {segment_name} ({block.getStart()} - {block.getEnd()})')
        current_address = block.getStart()
        block_end = address_offset(block.getEnd()) + 1
        while address_offset(current_address) + pointer_size <= block_end:
            value = read_pointer_value(program, current_address, pointer_size)
            if value:
                target_address = try_make_pointer_address(program, value)
                if target_address is not None and is_valid_target(program, target_address):
                    add_pointer_record(records, seen, program, current_address, target_address)
                    total += 1
            current_address = current_address.add(pointer_size)
    return total


def export_pointers(program, export_dir: Path, summary: ExportSummary) -> None:
    pointer_size = program.getDefaultPointerSize()
    records: list[dict[str, object]] = []
    seen: set[tuple[int, int]] = set()
    print(f'[*] Starting pointer scan. Pointer size: {pointer_size} bytes')
    data_xref_hits = collect_data_xrefs(program, records, seen)
    raw_pointer_hits = collect_raw_pointers(program, records, seen)
    records.sort(
        key=lambda item: (
            int(item['source_addr']),
            int(item['points_to']),
            str(item['source_seg']),
            str(item['target_name']),
            str(item['target_type']),
            str(item['target_detail']),
        )
    )
    lines = [
        f'# Total Pointers Found: {len(records)}',
        '# Format: Source_Address | Segment | Points_To_Address | Target_Name | Target_Type | Target_Detail',
        f'# Pointer size: {pointer_size}',
        f'# Data xref hits: {data_xref_hits}',
        f'# Raw pointer hits: {raw_pointer_hits}',
        '-' * 120,
    ]
    for record in records:
        lines.append(
            '{:X} | {} | {:X} | {} | {} | {}'.format(
                int(record['source_addr']),
                record['source_seg'],
                int(record['points_to']),
                record['target_name'],
                record['target_type'],
                record['target_detail'],
            )
        )
    write_text(export_dir / 'pointers.txt', '\n'.join(lines) + '\n')
    summary.pointer_count = len(records)
    print('[*] Pointers Summary:')
    print(f'    Data xref hits: {data_xref_hits}')
    print(f'    Raw pointer hits: {raw_pointer_hits}')
    print(f'    Unique pointer references exported: {summary.pointer_count}')


def export_binary_for_ai(binary_path: Path, export_dir: Path) -> ExportSummary:
    project_location = (Path('__tmp') / 'ghidra_projects').resolve()
    ensure_dir(project_location)
    ensure_dir(export_dir)
    summary = ExportSummary(export_dir=export_dir)
    print('=' * 60)
    print('Ghidra Export for AI Analysis')
    print('=' * 60)
    print(f'[+] Input binary: {binary_path}')
    print(f'[+] Export directory: {export_dir}')
    pyghidra.start()
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', DeprecationWarning)
        with pyghidra.open_program(
            str(binary_path),
            project_location=str(project_location),
            project_name=make_project_name(binary_path),
            analyze=True,
        ) as flat_api:
            program = flat_api.getCurrentProgram()
            print('[*] Exporting strings...')
            export_strings(program, export_dir, summary)
            print('')
            print('[*] Exporting imports...')
            export_imports(program, binary_path, export_dir, summary)
            print('')
            print('[*] Exporting exports...')
            export_exports(program, binary_path, export_dir, summary)
            print('')
            print('[*] Exporting pointers...')
            export_pointers(program, export_dir, summary)
            print('')
            print('[*] Exporting memory...')
            export_memory(program, export_dir, summary)
            print('')
            print('[*] Exporting decompiled functions...')
            export_decompiled_functions(flat_api, program, export_dir, summary)
    print('')
    print('=' * 60)
    print('[+] Export completed!')
    print(f'    Output directory: {summary.export_dir}')
    print('=' * 60)
    return summary


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    binary_path = Path(args.binary).expanduser().resolve()
    export_dir = resolve_export_dir(binary_path, args.export_dir)
    if not binary_path.is_file():
        parser.error(f'Input file does not exist: {binary_path}')
    export_binary_for_ai(binary_path, export_dir)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
