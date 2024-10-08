package test_issue_3849

test_require_context if {
	require_context("monkey", "eat", "banana") with input as {
		"principal": {"id": 101, "type": "monkey"},
		"action": "eat",
		"entity": {"id": 102, "type": "banana"},
	}
}

test_contrived if {
	allow with input as {
		"a": 101,
		"b": 101,
		"z": 101,
		"y": 101,
		"x": 101,
		"w": 101,
		"v": 101,
		"u": 101,
		"t": 101,
		"s": 101,
		"r": 101,
		"q": 101,
		"p": 101,
		"o": 101,
		"n": 101,
		"j": 101,
		"k": 101,
		"l": 101,
		"m": 101,
	}
}