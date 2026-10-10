from pathlib import Path
import json
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from source_hierarchy import source_hierarchy_context, source_hierarchy_hints


class SourceHierarchyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def source(self, name, text):
        path = self.root / name
        path.write_text(text)
        return path

    def context_json(self, hints, task="", **kwargs):
        text = source_hierarchy_context([], task, hints=hints, **kwargs)
        return text, json.loads(text.split("\n", 1)[1])

    def test_unknown_module_names_and_real_source_lines(self):
        path = self.source("fresh.v", """module vessel_az(input c, output q);
branch_k7 u_work(.c(c), .q(q));
endmodule
module branch_k7(input c, output q);
cell_vendor_x ff_78(.CP(c), .DATA(q));
endmodule
""")
        before = path.read_bytes()
        hints = source_hierarchy_hints([path], {"cell_vendor_x"})
        self.assertTrue(hints["complete"])
        self.assertEqual(hints["roots"], ["vessel_az"])
        self.assertEqual(hints["module_instances"], [{"parent": "vessel_az", "type": "branch_k7",
                         "instance": "u_work", "escaped": False, "source": str(path), "line": 2}])
        self.assertEqual(hints["library_leaf_instance_count"], 1)
        self.assertEqual(path.read_bytes(), before)

    def test_more_than_64_instances_do_not_turn_the_last_child_into_a_root(self):
        children = [f"module sapling_{index}(); endmodule" for index in range(93)]
        instances = [f"sapling_{index} limb_{index}();" for index in range(93)]
        path = self.source("tree.v", "module canopy();\n" + "\n".join(instances) + "\nendmodule\n" + "\n".join(children))
        hints = source_hierarchy_hints([path])
        self.assertTrue(hints["roots_complete"])
        self.assertEqual(hints["roots"], ["canopy"])
        self.assertEqual(len(hints["module_instances"]), 93)
        limited = source_hierarchy_hints([path], max_edges=3)
        self.assertEqual(limited["roots"], hints["roots"])
        self.assertEqual(limited["referenced_module_types"], hints["referenced_module_types"])
        self.assertTrue(limited["roots_complete"])
        self.assertFalse(limited["edges_complete"])
        self.assertFalse(limited["complete"])

    def test_cross_file_forward_definitions_have_one_complete_root_union(self):
        top = self.source("alpha.v", "module apex(); subtree first(); endmodule\n")
        child = self.source("beta.v", "module subtree(); unit_z below(); endmodule\n")
        leaf = self.source("gamma.v", "module unit_z(); endmodule\n")
        hints = source_hierarchy_hints([top, child, leaf])
        self.assertEqual(hints["roots"], ["apex"])
        self.assertTrue(hints["complete"])
        _, context = self.context_json(hints, "Apply scan constraints inside unit_z")
        match = next(row for row in context["module_instances"] if row["type"] == "unit_z")
        self.assertEqual(match["path"], "first/below")
        self.assertEqual(match["source"], str(child))
        self.assertEqual(match["line"], 1)

    def test_library_leaf_instances_do_not_retain_any_pin_graph(self):
        cells = "\n".join(f"unfamiliar_library ff_{i}(.D(d), .Q(q), .CLK(c));" for i in range(7000))
        path = self.source("flat.v", "module shell(input c, input d, output q);\n" + cells + "\nendmodule\n")
        hints = source_hierarchy_hints([path], {"unfamiliar_library"})
        self.assertTrue(hints["complete"])
        self.assertEqual(hints["module_instances"], [])
        self.assertEqual(hints["library_leaf_instance_count"], 7000)
        self.assertNotIn("ff_6999", json.dumps(hints))
        self.assertNotIn('"pins"', json.dumps(hints))

    def test_more_than_64_mib_does_not_disable_the_same_source_hierarchy(self):
        path = self.source("padded.v", "module large_shell(); module_part worker(); endmodule\n"
                           "module module_part(); endmodule\n")
        expected = source_hierarchy_hints([path])
        padding = ("// " + "p" * 1020 + "\n") * 256
        with path.open("a") as stream:
            for _ in range(257):
                stream.write(padding)
        self.assertGreater(path.stat().st_size, 64 * 1024 * 1024)
        self.assertEqual(source_hierarchy_hints([path]), expected)

    def test_escaped_module_and_instance_names_preserve_complete_paths(self):
        path = self.source("escaped.v", """module upper();
\\mod.part \\working[7].clock (.p(p));
endmodule
module \\mod.part (input p);
endmodule
""")
        hints = source_hierarchy_hints([path])
        self.assertTrue(hints["complete"])
        edge = hints["module_instances"][0]
        self.assertEqual(edge["type"], "mod.part")
        self.assertEqual(edge["instance"], "working[7].clock")
        self.assertTrue(edge["escaped"])
        _, context = self.context_json(hints)
        self.assertEqual(context["module_instances"][0]["path"], "working[7].clock")

    def test_escaped_names_containing_comment_markers_remain_names(self):
        path = self.source("escape_comments.v", "module outer();\ninner \\u/*literal*/ (.p());\nendmodule\nmodule inner(input p); endmodule\n")
        hints = source_hierarchy_hints([path])
        self.assertTrue(hints["complete"])
        self.assertEqual(hints["module_instances"][0]["instance"], "u/*literal*/")
        _, context = self.context_json(hints)
        self.assertFalse(context["module_instances"][0]["path_literal_unambiguous"])
        self.assertEqual(context["module_instances"][0]["segments"], ["u/*literal*/"])

    def test_comments_and_strings_do_not_invent_module_declarations(self):
        path = self.source("comments.v", """/* module phantom();
endmodule */
module actual();
localparam label="module invented(); endmodule";
// module shadow(); endmodule
endmodule
""")
        hints = source_hierarchy_hints([path])
        self.assertEqual([row["name"] for row in hints["modules"]], ["actual"])
        self.assertEqual(hints["roots"], ["actual"])

    def test_generate_parameterized_and_multiple_instances_remain_unknown(self):
        snippets = ["generate if (1) begin\nbranch g();\nend endgenerate",
                    "branch #(.WIDTH(2)) candidate();", "branch one(), two();"]
        for number, snippet in enumerate(snippets):
            with self.subTest(snippet=snippet):
                path = self.source(f"unknown_{number}.v", "module crown();\n" + snippet + "\nendmodule\nmodule branch(); endmodule\n")
                hints = source_hierarchy_hints([path])
                self.assertFalse(hints["complete"])
                self.assertFalse(hints["hierarchy_complete"])
                self.assertFalse(hints["roots_complete"])
                self.assertTrue(hints["issues"])

    def test_undefined_types_are_counted_without_claiming_valid_paths(self):
        path = self.source("missing.v", "module home();\n" + "\n".join(f"missing_definition obj_{i}();" for i in range(51)) + "\nendmodule\n")
        hints = source_hierarchy_hints([path])
        self.assertFalse(hints["complete"])
        self.assertEqual(hints["module_instances"], [])
        self.assertEqual(hints["undefined_instance_types"], [{"type": "missing_definition", "count": 51,
                         "source": str(path), "line": 2}])
        text, context = self.context_json(hints)
        self.assertFalse(context["roots_complete"])
        self.assertIn("must not justify rejecting an unseen object", text)

    def test_undefined_type_storage_limit_remains_explicitly_unknown(self):
        path = self.source("bounded_unknown.v", "module incomplete();\n" +
                           "\n".join(f"unknown_{i} sample_{i}();" for i in range(34)) + "\nendmodule\n")
        hints = source_hierarchy_hints([path], max_undefined_types=3)
        self.assertFalse(hints["complete"])
        self.assertFalse(hints["roots_complete"])
        self.assertFalse(hints["undefined_type_details_complete"])
        self.assertEqual(hints["undefined_type_overflow_instances"], 31)
        self.assertEqual(len(hints["undefined_instance_types"]), 3)

    def test_duplicate_modules_and_unparsed_declarations_are_explicitly_incomplete(self):
        for text, code in [("module twice(); endmodule\nmodule twice(); endmodule\n", "duplicate_module"),
                           ("module unknown(input [WIDTH-1:0] data); endmodule\n", "unparsed_port_declaration"),
                           ("module unknown(data);\ninput [WIDTH-1:0] data;\nendmodule\n", "unparsed_port_declaration")]:
            with self.subTest(code=code, text=text):
                path = self.source("invalid.v", text)
                hints = source_hierarchy_hints([path])
                self.assertFalse(hints["complete"])
                self.assertIn(code, hints["issue_counts"])

    def test_cycles_do_not_recurse_forever_or_claim_an_empty_complete_root_set(self):
        path = self.source("cycles.v", "module a(); b into_b(); endmodule\nmodule b(); a into_a(); endmodule\n")
        hints = source_hierarchy_hints([path])
        self.assertEqual(hints["roots"], [])
        self.assertFalse(hints["roots_complete"])
        self.assertFalse(hints["complete"])
        self.assertIn("cyclic_module_hierarchy", hints["issue_counts"])

    def test_conditional_macros_and_unterminated_blocks_are_unknown(self):
        for text in ["`ifdef OPTIONAL\nmodule selected(); endmodule\n`endif\n",
                     "module selected(); endmodule\n/* unfinished"]:
            with self.subTest(text=text):
                hints = source_hierarchy_hints([self.source("conditional.v", text)])
                self.assertFalse(hints["module_headers_complete"])
                self.assertFalse(hints["complete"])

    def test_missing_endmodule_and_nested_scope_do_not_claim_complete_roots(self):
        for text in ["module open_scope();\n", "module before();\nmodule after(); endmodule\n"]:
            with self.subTest(text=text):
                hints = source_hierarchy_hints([self.source("unclosed.v", text)])
                self.assertFalse(hints["module_headers_complete"])
                self.assertFalse(hints["roots_complete"])
                self.assertFalse(hints["complete"])

    def test_empty_inputs_do_not_claim_complete_module_or_root_knowledge(self):
        for paths in [[], [self.source("empty.v", "// no module declarations\n")]]:
            with self.subTest(paths=paths):
                hints = source_hierarchy_hints(paths)
                self.assertFalse(hints["complete"])
                self.assertFalse(hints["module_headers_complete"])
                self.assertFalse(hints["roots_complete"])
                self.assertIn("no_module_declarations", hints["issue_counts"])

    def test_task_relevant_paths_are_shown_before_unrelated_paths(self):
        path = self.source("relevant.v", "module head();\nplain neutral();\nclock_unit gate_bank();\nendmodule\n"
                           "module plain(); endmodule\nmodule clock_unit(); endmodule\n")
        hints = source_hierarchy_hints([path])
        _, context = self.context_json(hints, "Configure clock gating", max_paths=1)
        self.assertEqual(context["module_instances"][0]["path"], "gate_bank")
        self.assertFalse(context["paths_display_complete"])
        self.assertEqual(hints["roots"], ["head"])

    def test_bounded_display_keeps_json_complete_without_changing_root_analysis(self):
        path = self.source("many_roots.v", "\n".join(f"module root_{index}(); endmodule" for index in range(67)))
        hints = source_hierarchy_hints([path])
        text, context = self.context_json(hints, limit=1500)
        self.assertLessEqual(len(text), 1500)
        self.assertEqual(context["root_count"], 67)
        self.assertFalse(context["roots_display_complete"])
        self.assertTrue(context["roots_complete"])
        self.assertEqual(len(hints["roots"]), 67)

    def test_deep_path_display_limit_does_not_truncate_complete_root_analysis(self):
        declarations = [f"module layer_{index}(); layer_{index + 1} next_level(); endmodule" for index in range(83)]
        declarations.append("module layer_83(); endmodule")
        hints = source_hierarchy_hints([self.source("deep.v", "\n".join(declarations))])
        self.assertTrue(hints["complete"])
        _, context = self.context_json(hints, "inspect layer_83", max_depth=17)
        self.assertTrue(context["roots_complete"])
        self.assertFalse(context["path_traversal_complete"])
        self.assertEqual(context["roots"], ["layer_0"])
        self.assertTrue(all(len(row["segments"]) <= 17 for row in context["module_instances"]))

    def test_definition_pass_skips_leaf_connection_recognition(self):
        from unittest.mock import patch
        import source_hierarchy

        path = self.source("definition_only.v", "module shell();\n" +
                           "\n".join(f"unfamiliar_library ff_{index}(.D(d), .Q(q));" for index in range(51)) +
                           "\nendmodule\n")
        with patch.object(source_hierarchy, "_SIMPLE_NAMED_CONNECTIONS") as connections:
            records = list(source_hierarchy._records(path, 65536, {"unfamiliar_library"}, headers_only=True))
        connections.fullmatch.assert_not_called()
        self.assertEqual([text for text, _, _ in records], ["module shell()", "endmodule"])

    def test_header_optimization_matches_full_record_baseline_for_lexical_edges(self):
        from unittest.mock import patch
        import source_hierarchy

        full_records = source_hierarchy._records

        def original_record_pass(path, maximum, libraries=None, **_kwargs):
            return full_records(path, maximum, libraries, headers_only=False)
        sources = [
            "module root();\nleaf ff(.D(d));\n/* unfinished",
            "module root();\nunknown ff(.D(d));\n/* unfinished",
            'module root();\nleaf ff(.D(d));\nlocalparam label="unfinished',
            "module root();\nwire \\name;\nmodule nested(); endmodule\n",
            "module root();\nleaf ff(.D(" + "x" * 80 + "));\nendmodule\n",
            "module root(); leaf ff(.D(d)); endmodule\nmodule sub(); endmodule\n",
            "module root();\nunknown ff(.D(d))\n`ifdef OTHER\nendmodule\n`endif\n",
            "module root();\nleaf \\with;semicolon (.D(d));\nendmodule\n",
            "module root();\nassign q = d;\n// complete comment\nendmodule\n",
            "module root();\nwire q;\n/* comment */ module sub(); endmodule\n",
        ]
        for index, source in enumerate(sources):
            path = self.source(f"lexical_{index}.v", source)
            for maximum in (24, 65536):
                for libraries in ({"leaf"}, {"leaf", "module"}):
                    with self.subTest(index=index, max_statement_chars=maximum, libraries=libraries):
                        actual = source_hierarchy_hints([path], libraries, max_statement_chars=maximum)
                        with patch.object(source_hierarchy, "_records", side_effect=original_record_pass):
                            expected = source_hierarchy_hints([path], libraries, max_statement_chars=maximum)
                        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
