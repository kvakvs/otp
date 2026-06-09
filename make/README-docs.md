# Documentation Build Notes

## Toggleable Doctest Context Blocks

Generated ExDoc HTML supports display-only prolog and epilog lines for doctest
code examples. This is useful when an example needs setup or cleanup context,
but the main documentation should stay focused on the visible shell session.

The feature does not change `ct_doctest` execution. It only changes generated
HTML by adding a small button above selected code blocks. The button toggles the
configured prolog and epilog lines.

### Define Contexts

Define named contexts in the local `docs.exs` file with the OTP-specific
`doctest_contexts` key:

```elixir
[
  doctest_contexts: [
    setup_name: [
      prolog: """
      %% Hidden setup lines shown only when the context is expanded.
      1> application:ensure_all_started(my_app).
      {ok, _}
      """,
      epilog: """
      %% Hidden cleanup lines shown only when the context is expanded.
      3> application:stop(my_app).
      ok
      """
    ]
  ]
]
```

Both `prolog` and `epilog` are optional, but at least one should be present for
the context to have visible output.

### Select A Context For A Code Block

Place an HTML comment immediately before the code block:

````markdown
<!-- doctest-context: setup_name -->

```erlang
2> my_app:visible_example().
ok
```
````

In generated HTML, ExDoc renders the Erlang block normally. The OTP JavaScript
then finds the `doctest-context` marker and adds a `Show context` button above
the block. Expanding the button shows the configured prolog before the block and
the configured epilog after it.

### Notes

- The marker name must match a key in `doctest_contexts`.
- Unknown context names leave the code block unchanged and emit a browser
  console warning.
- Code blocks without a marker are unchanged.
- The feature is loaded through `make/ex_doc.exs` for all OTP ExDoc builds.
- Static assets live in `make/ex_doc_assets/`, and `make/doc.mk` includes them
  in `HTML_DEPS` so HTML rebuilds when the assets change.
