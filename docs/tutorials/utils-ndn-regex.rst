NDN Regular Expression
======================

NDN Regular Expression is used in two directions: matching and pattern&name
derivation. It is provides a way to represent name using pattern.

Name Component Matcher
----------------------------
A pattern for name is based on a list of name component matchers.

There are 2 types of name component matcher.

Exact Name Component Matcher
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Exact name component matcher matches the exact value of component. It is
enclosed by ``<`` and ``>`` with the value inside. For example, ``<abcd>`` can
match 1st component of ``/abcd/abc``, but it cannot match the 2nd component.

Wildcard Matcher
~~~~~~~~~~~~~~~~~~~~~~
``<>`` is a wildcard matcher that can match **ANY** component.

Wildcard Specializer
~~~~~~~~~~~~~~~~~~~~~~~~
Wildcard specializer is in between exact name component matcher and wildcard
matcher. It is a bracket-expression starting with ``'['`` and ending with
``']'``, the content inside the brackets could be either name component set or
a function name.

**Name Component Set** matches any single name component that is a member of
that set. Unlike the standard regular expression, NDN regular expression only
supports **Single Components Set**, that is, you have to list all the set
members one by one between the bracket. For example, ``[<ndn><localhost>]``
shall match a name component of either ``ndn"`` or ``localhost``.

When a name component set starts with a ``'^'``, the set becomes a
**Negation Set**, that is, it matches the complement of the name
components it contains. For example, ``[^<ndn>]`` shall match any name component
except ``ndn``.

Some other types of sets, such as Range Set, will be supported later.

**Function** specializes the pattern of a component.  For example,
``[timestamp]`` could be used to  match timestamp-format component.
Note that currently no function is supported.

NDN Regex Syntax
----------------

We borrow some syntaxes from standard regular expressions to build more
complicated name patterns.

Repeats
~~~~~~~

A component matcher can be followed by a repeat syntax to indicate how
many times the preceding component can be matched.

Syntax ``*`` for zero or more times. For example,
``<ndn><KEY><>*<ID-CERT>`` shall match ``/ndn/KEY/ID-CERT/``, or
``/ndn/KEY/edu/ID-CERT``, or ``/ndn/KEY/edu/ksk-12345/ID-CERT`` and so
on.

Syntax ``+`` for one or more times. For example,
``<ndn><KEY><>+<ID-CERT>`` shall match ``/ndn/KEY/edu/ID-CERT``, or
``/ndn/KEY/edu/ksk-12345/ID-CERT`` and so on, but it cannot match
``/ndn/KEY/ID-CERT/``.

Syntax ``?`` for zero or one times. For example,
``<ndn><KEY><>?<ID-CERT>`` shall match ``/ndn/KEY/ID-CERT/``, or
``/ndn/KEY/edu/ID-CERT``, but it cannot match
``/ndn/KEY/edu/ksk-12345/ID-CERT``.

Repetition can also be bounded:

``{n}`` for exactly ``n`` times. ``{n,}`` for at least ``n`` times.
``{,n}`` for at most ``n`` times. And ``{n, m}`` for ``n`` to ``m``
times.

Note that the repeat matching is **greedy**, that is it will consume as
many matched components as possible. We do not support non-greedy repeat
matching and possessive repeat matching for now.

Sub-pattern and Back Reference
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A section beginning ``(`` and ending ``)`` acts as a marked sub-pattern.
Whatever matched the sub-pattern is split out in a separate field by the
matching algorithms. For example ``([^<DNS>])<DNS>(<>*)<NS><>*`` shall
match a data name of NDN DNS NS record, and the first sub-pattern
captures the zone name while the second sub-pattern captures the
relative record name.

Marked sub-patterns can be referred to by a back-reference ``$n``. The
same example above shall match a name
``/ndn/edu/ucla/DNS/irl/NS/123456``, and a back reference ``$1$2`` shall
extract ``/ndn/edu/ucla/irl`` out of the name.

.. note::
    **Marked sub-patterns are NOT allowed inside a component matcher**

Pattern Inference
---------------------

NDN Regular Experssion also support pattern inference from original pattern.
Pattern Inference to derive patterns of original regex pattern with additional
knowledge. A list of arguments are required, the number of which should be equal
to the number of marked sub-patterns in the original pattern. The regex will
match its marked sub-patterns with these arguments so a more specific pattern
could be derived.

The input type should be a list of ndn names. Each name will replace the
relevant sub-pattern with an exact pattern. For example, if the original pattern
is ``<ndn><edu>(<>)(<>*)`` and ["/ucla", "/irl"] is passed to it. The inferred
pattern would be ``<ndn><edu><ucla><irl>``.

When an empty name is passed, it will remove the sub-pattern. For example, if
the original pattern is ``<ndn><edu>(<>)(<>*)`` and ["/ucla", "/"] is passed to
it. The inferred pattern would be ``<ndn><edu><ucla>``.

Name Derivation
--------------------

When a pattern only consists of determinate components and wildcard
specializers, an exact name could be derived from the pattern. If the wildcard
specializer is component set, name derived would take the first satisfied
component at that position. If the wildcard specializer is a function, the
relavant component would be generated by calling the function. Note that
generating component from function is not supported currently.

For example, name derivation of pattern ``<ndn><edu><ucla><irl>[<a><b>]``would
generate ``/ndn/edu/ucla/irl/a``.
