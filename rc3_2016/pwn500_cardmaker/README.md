# Overview
![Menu](https://puu.sh/so1iD/c828b85bea.png)

From the menu it looks like the standard setup for a UAF challenge.

### Creating greeting cards
We can create up to five greeting cards that have the following representation.

```C
struct card_st
{
  char to[50];
  char from[50];
  char ip_addr[16];
  short port;
  char border[10];
  char * contents;
};
```

These are stored in an array on `main`'s stack.  There doesn't appear to be anything too interesting that happens while setting these fields until we get to the `contents` pointer.  The program asks the user for the size of the message and gives that directly to malloc after adding `25` to it (the length of a constant suffix).  There is a check to make sure the user's size is not negative, but this is done by checking if the first character of the input is a `"-"`, which can be easily bypassed by prepending it with a space.

That seems like something we'd want to make use of, but as soon as we look to how the message gets written to the buffer it's clear that passing a negative size doesn't get us much.  It takes input using the `getline` function, which will reallocate the destination buffer if the input is larger than the destination's size.

### Listing card contents
Nothing too interesting here.  If we can overwrite the `card_st.contents` pointer somehow, we could use it to leak though.

### Changing card contents
Well, here's a pretty straightforward buffer overflow.  The size passed to `fgets` is calculated by `strlen(card_st.contents) + 3`.  So we can repeatedly call this, incrementing the size by a few bytes each time, and overflow as much as we want.

Not quite sure what there is to overflow into at this point though as the program doesn't store anything but text on the heap.  Metadata corruption is a possibility, but let's see if there's an easier bug to exploit first.

### Deleting cards
The way this is implemented, the `card_st.contents` pointer is freed and never nulled out.  Instead, the selected card and every card after it are shifted down in the array by one position, overwriting whatever was there before.

This results in the selected card's freed `card_st.contents` pointer overwriting that of the previous card.  So now we've got a UAF.

### Sending cards
This loops through all the cards, and pretty prints them over a socket to the `ip:port` pair specified in the card.
![normal card](https://puu.sh/so1rh/77d0bf15ab.png)

When it prints them out, however, the `card_st.border` string is passed to printf directly.  There's a 2 character limit for the border, but that's enough to use `"%p"` and get the following result.
![leak card](https://puu.sh/so1sL/9fed748cbc.png)

It might be hard to see in the image, but this gives us stack, heap, and libc leaks.

# Exploitation
So we've gone through the rest of the binary now and the UAF and buffer overflow seem to be all we've got.  There's still nothing interesting going on with the program's data, so metadata corruption seems to be the only real option for this.

We control the size of the allocations made and can write to them after they are freed.  Additionally, we have an unbounded overflow that we can potentially use to overwrite adjacent chunks.  We have leaked stack, heap, and libc addresses as well.

### Background
When `malloc` is passed a small size, the chunk that gets allocated is a fast chunk.  When this chunk is freed, it will be pushed onto the corresponding fastbin freelist, which is basically a singly linked list that functions as a LIFO stack.  If there is an entry in the freelist when `malloc` is called with a compatible size, it will be popped off the freelist and returned to the user.

### Plan
If we can control the forward pointer of a chunk in the fastbin freelist, we can make `malloc` return (almost) any address we want.  The only real limitation is that at the address we want, the value at the offset of the `size` metadata needs to be the same as the requested size.  So this rules out pointing it directly into the GOT.

Since we have a stack leak, we can instead have `malloc` return an address inside one of our card objects.  After creating more cards to cause our fake fastbin chunk to get popped off the freelist and returned from `malloc`, we can use the buffer overflow to overwrite the `card_st.contents` pointer of the card that we `malloc`'ed inside.  If we set the `card_st.contents` pointer to an address in the GOT, we can overwrite a function there with, for example, `system`.

### Implementation
 - create a card (A) to use for the leaks
 - create a card (B) and place a fake fastbin chunk inside its `to` field
 - delete B.  B's data will overwrite A's.  The fastbin freelist will look like: [  (B) -> 0  ]
 - edit A. We write the stack address of our fake chunk over the forward pointer of the freed B chunk.  The fastbin freelist will look like: [  (B) -> (fake) -> 0  ]
 - create a card (C) which will take B's old address.  The fastbin freelist will look like: [  (fake) -> 0  ]
 - create a card (D) which will be our fake chunk on the stack
 - overflow D over A's `card_st.contents` pointer and make it point to `free@got`
 - write `"/bin/sh"` as the message for one of the cards
 - delete that card.  this will "free" that card, i.e. call system with that card's message as the argument
 
![heap stuff](https://puu.sh/so0Ju/a327f9781c.jpg)

(note: the second malloc/first free are part of the leak function and can be ignored)

If we put all of that together and run it...

![win](https://puu.sh/snZUo/5dd1fbd072.png)



