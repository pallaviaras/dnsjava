// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.util.*;

/**
 * DNS Name Compression object.
 * @see Name
 *
 * @author Brian Wellington
 */

class Compression {

private class Entry {
	Name name;
	int pos;
	Entry next;
}

private static final int TABLE_SIZE = 17;

private Entry [] table;

/**
 * Creates a new Compression object.
 */
public
Compression() {
	table = new Entry[TABLE_SIZE];
}

/** Adds a compression entry mapping a name to a position.  */
public void
add(int pos, Name name) {
	int row = (name.hashCode() & 0x7FFFFFFF) % TABLE_SIZE;
	Entry entry = new Entry();
	entry.name = name;
	entry.pos = pos;
	entry.next = table[row];
	table[row] = entry;
}

/**
 * Retrieves the position of the given name, if it has been previously
 * included in the message.
 */
public int
get(Name name) {
	int row = (name.hashCode() & 0x7FFFFFFF) % TABLE_SIZE;
	for (Entry entry = table[row]; entry != null; entry = entry.next) {
		if (entry.name.equals(name))
			return (entry.pos);
	}
	return (-1);
}

}
