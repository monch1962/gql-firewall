# Sample 14: list-field-limiter.rego
# Topic: N+1 abuse prevention
#
# ATTACK: GraphQL resolvers often use N+1 query patterns — for each item
# in a list, the resolver executes a separate database query. An attacker
# who requests many list fields amplifies this cost:
#   { users { posts { comments { likes } } } }
# Each nesting level with a list multiplies the query count:
#   10 users × 10 posts × 10 comments = 1,000 database queries
#
# DEFENCE: Count the number of list-type fields requested. The firewall
# uses a heuristic: field names ending in "s" (plural) are likely lists.
# Block when the count exceeds a threshold.
#
# NOTE: The plural heuristic is not perfect. A field called "news" or
# "status" is not a list. For schema-aware list detection, integrate
# with the --schema flag (validates against SDL).
#
# PARAM: input.params.max_lists_requested (number, default 5)

package graphql

default allow := false

allow if {
    count(deny) == 0
}

deny contains msg if {
    input.params.max_lists_requested
    input.lists_requested > input.params.max_lists_requested
    msg := sprintf("too many list fields requested (%d)", [input.lists_requested])
}

# ── Tests ───────────────────────────────────────────────────────────────────

test_reasonable_list_count_allowed if {
    allow with input as {
        "depth": 2, "field_count": 4, "operation_type": "query",
        "field_paths": ["users", "users.name", "posts", "posts.title"],
        "lists_requested": 2,
        "params": {"max_lists_requested": 5}
    }
}

test_excessive_list_fields_blocked if {
    some msg in deny with input as {
        "depth": 2, "field_count": 15, "operation_type": "query",
        "field_paths": ["a", "b", "c", "d", "e", "f"],
        "lists_requested": 20,
        "params": {"max_lists_requested": 5}
    }
    startswith(msg, "too many list fields requested (20)")
}
