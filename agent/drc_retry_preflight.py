"""Reject narrowly identifiable retries that cannot change prior clock-control DRC failures."""
from __future__ import annotations

import re
from typing import Any, Callable, Iterable

from dofile_recipe import tcl_chunks


_SIGNAL_TYPES = {"clock", "reset", "constant", "scan_enable"}
_CONTROL_COMMANDS = {"set_scan_signal", "set_scan_drc_cfg", "set_dft_clock_gating_cfg"}
_CHAIN_ONLY = {"-si_port_format", "-so_port_format", "-max_length", "-chain_count"}
_READ_ONLY = {"get_cells", "get_obj_insts", "get_pins", "get_obj_pins", "get_ports",
              "get_obj_ports", "get_nets", "get_obj_nets", "get_property", "get_attribute"}


def _literal(word: str, words_for: Callable[[str], list[str]]) -> str | None:
    if word.startswith("{") and word.endswith("}"):
        # Tcl braced words preserve literal indexed pin names and suppress substitution.
        return word[1:-1]
    if word.startswith('"') and word.endswith('"'):
        word = word[1:-1]
    if word.startswith("[") and word.endswith("]"):
        words = words_for(word[1:-1])
        if words and words[0] == "list":
            values = [_literal(value, words_for) for value in words[1:]]
            if all(value is not None and not re.search(r"\s", value) for value in values):
                return " ".join(values)
        return None
    return None if re.search(r"[$\[\]\\;\n]", word) else word


def _readonly_argument(word: str, words_for: Callable[[str], list[str]]) -> bool:
    if word.startswith("{") and word.endswith("}"):
        return True
    if word.startswith('"') and word.endswith('"'):
        word = word[1:-1]
    if "[" not in word and "]" not in word:
        return "\\" not in word  # Variable lookup alone cannot execute a control command.
    if not word.startswith("[") or not word.endswith("]"):
        return False
    words = words_for(word[1:-1])
    if not words:
        return False
    if words[0] == "file":
        safe_command = len(words) >= 2 and words[1] in {"join", "dirname", "normalize", "tail", "rootname"}
        arguments = words[2:]
    else:
        safe_command = words[0] in _READ_ONLY
        arguments = words[1:]
    return safe_command and all(_readonly_argument(argument, words_for) for argument in arguments)


def _pairs(words: list[str], words_for: Callable[[str], list[str]]) -> tuple[tuple[str, str], ...] | None:
    if len(words) % 2:
        return None
    pairs = []
    for option, value in zip(words[::2], words[1::2]):
        literal = _literal(value, words_for)
        if not re.fullmatch(r"-[a-z_]+", option) or literal is None:
            return None
        pairs.append((option, literal))
    if len({option for option, _ in pairs}) != len(pairs):
        return None
    return tuple(sorted(pairs))


def _configuration(script: str, words_for: Callable[[str], list[str]]) -> tuple | None:
    """Recognize only flat commands and pure output/probe setup; unknown Tcl opts out."""
    try:
        chunks = tcl_chunks(script.replace("\\\n", " "))
    except ValueError:
        return None
    commands = []
    for chunk in chunks:
        text = chunk.strip()
        if not text or text.startswith("#"):
            continue
        words = words_for(text)
        if not words or any(";" in word for word in words):
            return None
        name = words[0]
        io = name.startswith(("rpt_", "dump_")) or name in _READ_ONLY or name == "puts"
        io = io or name == "file" and len(words) >= 2 and words[1] == "mkdir"
        if io and all(_readonly_argument(word, words_for) for word in words[1:]):
            commands.append(("io", words, text))
        elif name == "set" and len(words) == 3 and re.fullmatch(r"[A-Za-z_]\w*", words[1]):
            if not _readonly_argument(words[2], words_for):
                return None
            commands.append(("binding", words, text))
        else:
            # Tcl blocks, source/eval and other dynamic configuration have no narrow proof.
            if name in {"if", "foreach", "for", "while", "proc", "source", "eval", "uplevel", "namespace"}:
                return None
            commands.append(("configuration", words, text))
    substantive, controls = [], []
    full_insert = False
    design, partition = "", "Default_Partition"
    for category, words, text in commands:
        name = words[0]
        if category == "io":
            continue
        if category == "binding":
            variable = words[1]
            reference = re.compile(r"\$(?:" + re.escape(variable) + r"\b|\{" + re.escape(variable) + r"\})")
            # Ignore setup used only by reports/output paths or probes, including unused probes.
            uses = [kind for kind, other, source in commands if other is not words and reference.search(source)]
            if all(kind in {"io", "binding"} for kind in uses):
                # A binding consumed by another binding might flow to substantive configuration.
                if any(kind == "binding" for kind in uses):
                    return None
                continue
        if name in _CONTROL_COMMANDS:
            options = _pairs(words[1:], words_for)
            if options is None:
                return None
            if name != "set_scan_signal" or dict(options).get("-type") in _SIGNAL_TYPES:
                if name == "set_scan_signal" and ("-type" not in dict(options) or "-port" not in dict(options)):
                    return None
                controls.append((design, partition, name, options))
                continue
            if "-type" not in dict(options):
                return None
            # Other signal declarations affect DFT configuration and remain substantive.
        if name == "set_scan_cfg":
            options = _pairs(words[1:], words_for)
            if options is None:
                return None
            remaining = tuple(pair for pair in options if pair[0] not in _CHAIN_ONLY)
            if remaining:
                substantive.append((name, remaining))
            continue
        literal = tuple(_literal(word, words_for) for word in words)
        if any(word is None for word in literal):
            return None
        if name == "present_design" and len(words) == 2:
            design, partition = literal[1], "Default_Partition"
        elif name == "set_current_scan_partition" and len(words) == 2:
            partition = literal[1]
        elif name == "insert_dft_logic":
            full_insert |= not any(re.fullmatch(r"-\w+_only|-replace_unscan", word) for word in literal[1:])
            if len(literal) == 1:
                # Adding bare full insertion after an unresolved diagnostic does
                # not change the control configuration that produced that DRC.
                continue
        substantive.append(literal)
    return tuple(controls), tuple(substantive), full_insert


def unchanged_control_retry_problems(previous_dofile: str, candidate_dofile: str,
                                     previous_unallowed_codes: Iterable[str], *,
                                     netlist_edits: Any = None,
                                     words_for: Callable[[str], list[str]]) -> list[str]:
    """Call after script adapters, passing only codes from actual unpermitted DRC results.

    Proposed netlist edits bypass this guard, never the caller's mandatory EQY
    admission. Dynamic or otherwise unrecognized configuration also opts out.
    """
    codes = {re.sub(r"[-_ ]", "", str(code)).upper() for code in previous_unallowed_codes}
    relevant = codes & {"DFTR1", "DFTR8", "DFTR9"}
    if not relevant or netlist_edits:
        return []
    previous = _configuration(previous_dofile, words_for)
    candidate = _configuration(candidate_dofile, words_for)
    if previous is None or candidate is None or not candidate[2]:
        return []
    if previous[:2] != candidate[:2]:
        return []
    return ["Prior actual unpermitted " + ", ".join(sorted(relevant)) +
            " remains unsupported by any control or substantive configuration change. "
            "Changing only reports, outputs, SI/SO naming or chain count/length cannot repair it. "
            "Change the relevant clock/reset/constant/scan-enable, DRC or clock-gating configuration; "
            "propose an EQY-checked netlist edit; or omit full insertion for a connectivity diagnostic round."]
