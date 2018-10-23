# Groot

The binary implements a filesystem which we can interact with using common shell commands.  The filesystem is implemented as a tree structure, with nodes as follows.
```
struct file
{
    u64 type;
    file * parent;
    file * children;
    file * siblings;
    char * name;
    char * content;
};
```

The root directory node, the head of the tree, is located in the .data section of the binary.  It is created and initialized, along with some dummy files and directories, at the beginning of `main`.  File nodes other than the root are allocated on the heap.

### The bug
When creating a new file or directory, the `file->children` field is uninitialized.  Additionally, when freeing a file node none of its fields are zeroed out.

This means that when we do the following operations, `reclaim->children` points to the freed memory of the subdirectory.
```
mkdir outer
cd outer
mkdir inner
cd ..
rm outer
mkdir reclaim
```

At this point, despite having a UAF, we're limited in that all data we control is allocated onto the heap via `strdup`.  As `strdup` will stop copying once it reaches a null byte, we aren't able to reclaim the freed object without creating a non-null string at least long enough to put it in the same size heap chunk as a file node (0x30 bytes, 0x40 bin).  The only field we could overwrite in this case is `file->content`, which we can't access as we can only reference it by name, which is necessarily overwritten with an invalid pointer.  Even if this weren't the case, the binary is PIE so we don't know the address of anything.

### The (first) leak

At this point, one thing that's interesting is that if we do `ls reclaim`, we get the following output.
```
. .. reclaim
```

So it looks like the argument we passed to `ls` got written over the `inner->name` pointer.  But what happens if we make the directory names differently sized such that they end up in different bins on the heap?
```
. ..
```

That seems odd at first, but it turns out that the name string is being placed into the tcache when it's freed, and as there's nothing else in that bin at the time, its (tcache) `next` pointer is `NULL`.  So `ls` is actually still printing it out, but it's just an empty string.

Now, if we place some correctly sized objects into the tcache beforehand, we get a heap leak. `inner->name`'s tcache `next` pointer is now pointing to the next object in the tcache freelist.
```
.    ..    0C\x9e\x8c\xfeU
```

Even with a heap leak, the `strdup` limitation is really killing us here.  There's not really anything in the binary's functionality that'll let us move on from this, so we need to start looking into heap metadata corruption.

### Tcache background
For some background, the tcache is a new feature of glibc's malloc implementation that is intended to provide performance improvements for multithreaded code.  From a high level perspective, the tcache is effectively the same as fastbins, except that there are (almost?) no security considerations.

When heap allocations below a certain size are freed, they will be placed into a tcache freelist based on their size (if it isn't full, otherwise they'll go to fastbins).  A singly linked list is used to keep track of the freed chunks in each bin, and new additions are inserted at the head.  When a heap allocation is made of a size that matches that of a non-empty tcache bin, the top chunk in the freelist is returned and its `next` pointer is made to be the new head.

### Getting a write

When we leaked out that heap address, we did it by running `ls` on the reclaimed `outer` directory -- the program thinks that address is the name of a valid file.  The file it actually corresponds to is the `inner` directory that we freed, though.  So what happens if we free it again?
```
rm outer/0C\x9e\x8c\xfeU
```

Well, it didn't segfault at least.  And the tcache looks pretty interesting.
```
(0x20)   tcache_entry[0]: 0x55bc6abdc3c0 --> 0x55bc6abdc3c0 // the name chunk
(0x40)   tcache_entry[2]: 0x55bc6abdcbc0 --> 0x55bc6abdcbc0 // the file chunk
```

So we've got the tcache entries for both `inner` and its `name` looping back to themselves.  If we allocate a new string in the 0x20 bin, the head of the 0x20 tcache bin will be the chunk we just allocated.  Since we control the contents of that string, we can change the tcache `next` pointer to an arbitrary value.
```
mkdir AAAAAAAA
(0x20)   tcache_entry[0]: 0x55bc6abdc3c0 --> 4141414141414141
```

We then make an allocation to take up the second reference to the freed name (just to get it off the list, doesn't matter what it contains).
```
mkdir BBBBBBBB
(0x20)   tcache_entry[0]: 4141414141414141 -> ?????
```

Now, the next allocation we make from the 0x20 tcache bin will be at an entirely controlled address.  We have an arbitrary write.

### Actually doing something useful with the write...

There are no function pointers on the heap, or anything else that'd let use directly take control of `rip`.  We also don't have a `.text` or libc leak.  While it's possible to get libc pointers on the heap, it'd involve more metadata corruption in this case.  But we were tired and just wanted to finish this, and there are pointers to the binary's `.data` section on the heap, and pointers to libc in the `.got`, so we just went that route.

All the files/directories in the root `/` directory have pointers to the binary's `.data` section (`parent`).  We can calculate the address of a `file` object with a relative offset from our initial heap leak, as well as the address of a file object's `parent` pointer.  If we use the write to overwrite the `file->contents` pointer with the address of the `.data` pointer, we can `cat` the file to get a leak of the binary.

With a leak of the binary, we can now do the same thing, except instead of leaking out a `.data` pointer from the heap, we can leak out a libc pointer from the `.got`.

Now that we have a libc leak, we can overwrite `malloc_hook` with a one-gadget-win to get a shell.
