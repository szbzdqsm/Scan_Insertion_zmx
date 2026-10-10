"""Union actual Liberty sequential groups without guessing from cell names."""
from __future__ import annotations

import re
from typing import Iterable


_GROUP = re.compile(r'(?:^|[{};])\s*(ff_bank|latch_bank|ff|latch)\s*\([^()]*\)\s*\{')
_KIND_TOKEN = re.compile(r'\b(?:ff|latch)(?:_bank)?\b')
_PENDING_GROUP = re.compile(r'(?:^|[{};])\s*(?:ff_bank|latch_bank|ff|latch)\b[^{};]*\Z')
_DYNAMIC = re.compile(r'[$\[\]\\;\s]')


class LibraryCellCatalog(set):
    """Set of names with conservative evidence about each observed definition.

    Call ``add`` once per real cell definition, then ``observe_line`` for each
    source line associated with that cell. Definitions without a recognized
    sequential group remain unknown. Multiple supplied definitions never let
    one definition erase another definition's unknown or conflicting kind.
    """

    def __init__(self, names: Iterable[str] = ()):
        super().__init__()
        self.ff_cells: set[str] = set()
        self.latch_cells: set[str] = set()
        self.ff = self.ff_cells
        self.latch = self.latch_cells
        self._definitions: dict[str, list[set[str]]] = {}
        self._active_cell = ''
        self._active_definition: set[str] | None = None
        self._block_comment = False
        self._quoted = False
        self._escaped = False
        self._tail = ''
        for name in names:
            self.add(name)

    def add(self, cell_name: str) -> None:
        super().add(cell_name)
        definition: set[str] = set()
        self._definitions.setdefault(cell_name, []).append(definition)
        self._active_cell = cell_name
        self._active_definition = definition
        self._tail = ''

    def update(self, *iterables: Iterable[str]) -> None:
        for iterable in iterables:
            for cell_name in iterable:
                self.add(cell_name)

    @property
    def unknown_cells(self) -> set[str]:
        return {name for name in self if not self._definitions.get(name) or
                any(not kinds for kinds in self._definitions[name])}

    def kinds(self, cell_name: str) -> frozenset[str]:
        if cell_name not in self:
            return frozenset()
        definitions = self._definitions.get(cell_name, [])
        result = set().union(*definitions) if definitions else set()
        if not definitions or any(not kinds for kinds in definitions):
            result.add('unknown')
        return frozenset(result)

    def is_latch_only(self, cell_name: str) -> bool:
        return self.kinds(cell_name) == {'latch'}

    def _literal_text(self, line: str) -> str:
        """Blank strings/comments while keeping group punctuation and lines."""
        output = []
        index = 0
        while index < len(line):
            character = line[index]
            following = line[index:index + 2]
            if self._block_comment:
                if following == '*/':
                    self._block_comment = False
                    output.append('  ')
                    index += 2
                else:
                    output.append('\n' if character == '\n' else ' ')
                    index += 1
                continue
            if self._quoted:
                output.append('\n' if character == '\n' else ' ')
                if self._escaped:
                    self._escaped = False
                elif character == '\\':
                    self._escaped = True
                elif character == '"':
                    self._quoted = False
                index += 1
                continue
            if following == '//':
                output.append('\n' if line.endswith('\n') else '')
                break
            if following == '/*':
                self._block_comment = True
                output.append('  ')
                index += 2
            elif character == '"':
                self._quoted = True
                self._escaped = False
                output.append(' ')
                index += 1
            else:
                output.append(character)
                index += 1
        return ''.join(output)

    def observe_line(self, cell_name: str, line: str) -> None:
        literal = self._literal_text(line)
        if not cell_name:
            self._tail = ''
            return
        if self._active_cell != cell_name or self._active_definition is None:
            self.add(cell_name)
        # Real group headers can continue across lines. Keep bounded lexical
        # context; truncation can miss a group but cannot invent a cell kind.
        if not self._tail and not _KIND_TOKEN.search(literal):
            return
        combined = self._tail + literal
        consumed = 0
        for group in _GROUP.finditer(combined):
            kind = 'ff' if group[1] in {'ff', 'ff_bank'} else 'latch'
            self._active_definition.add(kind)
            (self.ff_cells if kind == 'ff' else self.latch_cells).add(cell_name)
            consumed = group.end()
        # Retain only an incomplete candidate header, not large cell bodies.
        # This makes ordinary Liberty timing tables cheap to observe.
        pending = _PENDING_GROUP.search(combined[consumed:])
        self._tail = pending.group() if pending and len(pending.group()) <= 8192 else ''
        if pending and len(pending.group()) > 8192:
            self._active_definition.add('unknown')


def mapping_kind_problems(words: list[str], catalog: set[str]) -> list[str]:
    """Reject a literal FF mapping endpoint only when Liberty proves latch-only."""
    if not isinstance(catalog, LibraryCellCatalog) or len(words) != 3 or words[0] != 'set_scan_cell_mapping':
        return []
    problems = []
    for role, word in zip(('source', 'target'), words[1:]):
        literal = word[1:-1] if word[:1] in {'"', '{'} and word[-1:] in {'"', '}'} else word
        if not literal or _DYNAMIC.search(literal):
            continue
        if catalog.is_latch_only(literal):
            problems.append(f"set_scan_cell_mapping {role} '{literal}' is a latch-only cell in the actual supplied Liberty; "
                            'the command requires flip-flop cells. Preserve latches and map actual FFs.')
    return problems
