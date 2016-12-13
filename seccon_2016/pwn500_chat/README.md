## Overview
The program is a twitter type thing, where users can post public tweets as well as send direct messages to each other.  Tweets can be deleted by their associated user, and all tweets associated with a user are deleted when the user is deleted.  Users can also change their name.

Tweets are of the form
```C
struct tweet
{
  uint32_t id;
  uint32_t padding;
  user * user;
  char msg[128];
  tweet * prev;
};
```

and users are of the form
```C
struct user
{
  char * name;
  tweet * last_tweet;
  user * prev;
};
```

### The bug
When a user is created their name is read into a 32 byte buffer on the stack.  A `user` struct is then allocated, and the `name` field is set to `strdup(name)`.  When changing a user's name, however, it will write up to 32 bytes into the buffer.  If the initial name was shorter than 32 bytes it will overflow.

## Exploitation
By overwriting the name pointer of a user we can get both a leak and an arbitrary write.  However, with a one character name, the most we can overflow is into the `prev_size` and `chunk_size` metadata fields of the next chunk.  By modifying the `chunk_size` of a chunk in the unsorted bin, we can cause subsequent allocations to overlap with already allocated chunks.  If we can get the `msg` field of a `tweet` to overlap with a `user`, we can overwrite the `name` pointer.

### Process
* Create two users `A` and `B`
* Login as `B` and create a public tweet
* Logout and create two more users `C` and `D`
* The heap looks like `[user A] [user B] [tweet B] [user C] [user D]`
* Login again as `B` and delete the tweet
* The heap looks like `[user A] [user B] [free chunk] [user C] [user D]`
* Change `B`'s name to overflow into the freed chunk's metadata and overwrite `chunk_size` with `0xff1`
* Login as `D` and create two public tweets
* The heap looks like: 
```
[user A] [user B] [tweet D (1)] [user C] [user D]
                                [      tweet D (2)      ]
```
* For the second tweet, the `name` pointer of user `D` is at offset `0x30` in the `msg` field.
* We can then overwrite `name` with the address of `strchr`'s `GOT` entry
* When we view the tweet, it will print out the name of the user associated with it.  As `name` is now pointing into the `GOT`, it will leak out `strchr`'s address.
* Now that we have a libc leak, we can calculate the address of a one-gadget-win and overwrite `strchr` with it by changing the user's name.
* The next time `strchr` is called it drops us into a shell


![heap](http://puu.sh/sNqjv/60e68b4bf3.png)
![flag](http://puu.sh/sNufX/7e59ff7e96.png)
