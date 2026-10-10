"""Tiny real-shaped Liberty fixtures for conservative sequential categories."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'agent'))
from library_cell_catalog import LibraryCellCatalog, mapping_kind_problems  # noqa: E402


def observe(catalog, name, text):
    catalog.add(name)
    for line in text.splitlines(keepends=True):
        catalog.observe_line(name, line)


class LibraryCellCatalogTests(unittest.TestCase):
    def test_real_sky_library_group_shape_has_no_name_guess(self):
        catalog = LibraryCellCatalog()
        observe(catalog, 'ordinary', '''cell ("ordinary") {
    latch ("IQ","IQ_N") {
        next_state : "D";
        enable : "!GATE";
    }
}
''')
        observe(catalog, 'scanned', '''cell ("scanned") {
    ff ("IQ","IQ_N") { clocked_on : "CLK"; }
    test_cell () {
        ff ("IQ","IQ_N") { next_state : "D"; }
    }
}
''')
        self.assertEqual(catalog.kinds('ordinary'), {'latch'})
        self.assertEqual(catalog.kinds('scanned'), {'ff'})
        self.assertTrue(catalog.is_latch_only('ordinary'))
        self.assertFalse(catalog.is_latch_only('scanned'))
        self.assertEqual(catalog, {'ordinary', 'scanned'})

    def test_bank_groups_and_multiline_headers_are_supported(self):
        catalog = LibraryCellCatalog()
        observe(catalog, 'ff_array', 'ff_bank\n("IQ", "IQ_N", 4)\n{\n}\n')
        observe(catalog, 'latch_array', 'latch_bank ("IQ", "IQ_N", 2) { }\n')
        self.assertEqual(catalog.ff_cells, {'ff_array'})
        self.assertEqual(catalog.latch_cells, {'latch_array'})

    def test_names_never_prove_kind(self):
        catalog = LibraryCellCatalog(['dff_name', 'scan_latch_name'])
        self.assertEqual(catalog.kinds('dff_name'), {'unknown'})
        self.assertFalse(catalog.is_latch_only('scan_latch_name'))
        self.assertEqual(catalog.kinds('missing'), set())

    def test_unknown_duplicate_definition_prevents_rejection(self):
        catalog = LibraryCellCatalog()
        observe(catalog, 'duplicate', 'latch (IQ, IQ_N) { }\n')
        observe(catalog, 'duplicate', 'area : 4;\n')
        self.assertEqual(catalog.kinds('duplicate'), {'latch', 'unknown'})
        self.assertFalse(catalog.is_latch_only('duplicate'))
        self.assertIn('duplicate', catalog.unknown_cells)

    def test_ff_latch_conflict_and_duplicate_known_definitions_take_union(self):
        catalog = LibraryCellCatalog()
        observe(catalog, 'duplicate', 'latch (IQ, IQ_N) { }\n')
        observe(catalog, 'duplicate', 'ff (IQ, IQ_N) { }\n')
        self.assertEqual(catalog.kinds('duplicate'), {'latch', 'ff'})
        self.assertFalse(catalog.is_latch_only('duplicate'))
        observe(catalog, 'known', 'latch (IQ, IQ_N) { }\n')
        observe(catalog, 'known', 'latch (IQ, IQ_N) { }\n')
        self.assertTrue(catalog.is_latch_only('known'))

    def test_comments_and_strings_do_not_invent_sequential_groups(self):
        catalog = LibraryCellCatalog()
        observe(catalog, 'unknown', '''// latch (IQ, IQ_N) { }
/* ff (IQ, IQ_N) {
   latch (IQ, IQ_N) { } */
function : "ff (IQ, IQ_N) { }";
comment : "escaped \\" latch (IQ, IQ_N) { }";
ff_not_a_group (IQ, IQ_N) { }
foo_ff (IQ, IQ_N) { }
ff (IQ, IQ_N);
''')
        self.assertEqual(catalog.kinds('unknown'), {'unknown'})

    def test_inline_comments_and_real_group_after_comment(self):
        catalog = LibraryCellCatalog()
        observe(catalog, 'actual', '/* fake latch(a,b) { } */ ff (IQ, IQ_N) { } // latch(a,b) { }\n')
        self.assertEqual(catalog.kinds('actual'), {'ff'})

    def test_comment_state_is_preserved_across_lines_and_cell_names(self):
        catalog = LibraryCellCatalog()
        catalog.add('first')
        catalog.observe_line('first', '/* opening\n')
        catalog.add('second')
        catalog.observe_line('second', 'latch (a, b) { }\n')
        catalog.observe_line('second', '*/ ff (IQ, IQ_N) { }\n')
        self.assertEqual(catalog.kinds('second'), {'ff'})
        self.assertEqual(catalog.kinds('first'), {'unknown'})

    def test_mapping_source_and_target_require_proven_latch_only(self):
        catalog = LibraryCellCatalog()
        observe(catalog, 'latch_cell', 'latch (IQ, IQ_N) { }\n')
        observe(catalog, 'ff_cell', 'ff (IQ, IQ_N) { }\n')
        catalog.add('unknown')
        self.assertEqual(len(mapping_kind_problems(['set_scan_cell_mapping', 'latch_cell', 'ff_cell'], catalog)), 1)
        self.assertEqual(len(mapping_kind_problems(['set_scan_cell_mapping', 'ff_cell', 'latch_cell'], catalog)), 1)
        self.assertEqual(mapping_kind_problems(['set_scan_cell_mapping', 'unknown', 'ff_cell'], catalog), [])
        self.assertEqual(mapping_kind_problems(['set_scan_cell_mapping', 'latch_cell', 'ff_cell'], set(catalog)), [])

    def test_literal_quotes_and_dynamic_tcl_are_not_confused(self):
        catalog = LibraryCellCatalog()
        observe(catalog, 'latch_cell', 'latch (IQ, IQ_N) { }\n')
        self.assertEqual(len(mapping_kind_problems(['set_scan_cell_mapping', '{latch_cell}', 'unknown'], catalog)), 1)
        self.assertEqual(len(mapping_kind_problems(['set_scan_cell_mapping', '"latch_cell"', 'unknown'], catalog)), 1)
        for words in [['set_scan_cell_mapping', '$latch_cell', 'unknown'],
                      ['set_scan_cell_mapping', '[get_cells latch_cell]', 'unknown'],
                      ['set_scan_cell_mapping', 'latch_cell'], ['unrelated', 'latch_cell', 'unknown']]:
            with self.subTest(words=words):
                self.assertEqual(mapping_kind_problems(words, catalog), [])

    def test_observe_implicitly_registers_cell_and_update_keeps_set_behavior(self):
        catalog = LibraryCellCatalog()
        catalog.observe_line('ff_cell', 'ff (IQ, IQ_N) { }\n')
        catalog.update(['a', 'b'])
        self.assertEqual(catalog, {'ff_cell', 'a', 'b'})
        self.assertEqual(catalog.kinds('ff_cell'), {'ff'})
        self.assertEqual(catalog.kinds('a'), {'unknown'})


if __name__ == '__main__':
    unittest.main()
