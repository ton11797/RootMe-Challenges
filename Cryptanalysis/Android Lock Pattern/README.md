# Android Lock Pattern
https://www.root-me.org/en/Challenges/Cryptanalysis/System-Android-lock-pattern

```
Having doubts about the loyalty of your wife, you’ve decided to read SMS, mail, etc in her smarpthone. Unfortunately it is locked by schema. In spite you still manage to retrieve system files.
You need to find this test scheme to unlock smartphone.
NB : validation password is a number (archive sha256 is 525daa911d4dddb7f3f4b4ec24bff594c4a1994b2e9558ee10329144a6657f98)
```

So the description says it all - in order to solve the challenge, the pattern that locks the phone needs to be cracked.<br>
In Android, when a pattern is set then a _gesture.key_ file is generated, with a SHA-1 hash of the actual pattern values.<br>
After a quick search, the _gesture.key_ file's path seems to be **/data/system/gesture.key**, and it's content is **2c3422d33fb9dd9cde87657408e48f4e635713cb**.<br><br>

After the hash is found, it needed to be reversed. Fortunately, someone created a "rainbow tables" for this purpose (it's actually a SQLite database containing 986328 records).<br>
So, after getting the database (uploaded to this repository), running the next SQL query would find the pattern:

```base
sqlite> SELECT * FROM RainbowTable WHERE hash="2c3422d33fb9dd9cde87657408e48f4e635713cb";
2c3422d33fb9dd9cde87657408e48f4e635713cb|[1, 4, 5, 2, 6, 3, 7, 8, 0]
```

The pattern is [1, 4, 5, 2, 6, 3, 7, 8, 0]. According to the description it should be a number.  
So, The flag is **145263780**.<br>
