# Firewall

### TESTING
I tested my program initially on the provided output, but then added some cases just to make sure I was sorting correctly.
Eventually I used the `main` function to test by checking the inclusivity of the ranges of both IPs and ports.
Basically, if a rule had a range `a to b`, I tested `a-1` and `b+1` to make sure they were false and `a` and `b` to make sure they were true. I also tested for the smallest and largest case.

### DESIGN
I didn't have a lot of time to worry about design, so I just implemented one of the three ideas that immediately popped into my head. The first one was binary search, as it seemed to me to be the most obvious one (as matching a rule is basically finding it). This would take `O(nlogn)` time to fill into the rule storage data structure, and then subsequently `O(logn)` for every find. The hashing method I then thought of would take average case of `O(1)` for every find, but that idea was discarded after 30 seconds when I realized that if the csv file only had one entry `<inbound, udp, 0-65535, 0.0.0.0-255.255.255.255>` I'd be stuck there hashing 2^48 entries... I also considered a tree, but it was discarded immediately because it had the same overhead problem the hashing method had, without the constant runtime.
As for another small design choice, I decided to write a function to serialize the direction and protocol. Looking at my current implementation, I don't need it, but it was written mainly because I thought I was going to hash the entries, so I started writing it to not waste time. In the case I did hash, it would mean approximately 9-10 fewer digits to hash. However, the littly overhead it takes to serialize still saves me some time in comparisons, and even though the asymptotic runtime isn't affected, I'll take what I can get.

### OPTIMIZATIONS
I have a couple issues with my code. First of all, I couldn't optimize the `std::binary_search` with a lambda expression using the STL, because the STL only takes comparators that return booleans, and my compare function returned an integer, just like `std::string.compare()`. It definitely could have made my code a little bit cleaner. Unfortunately, I just ran out of time. 

Also, I would have liked to clean up my parsing function a little bit. I'm sure there's better ways than getline and stringstreams, but this is just what I was familiar with. I'm sure I could have parsed it based on commas instead of traversing the whole string to turn commas (and dashes) into spaces (for stringstream). Because I wasn't great at parsing it, I could be traversing the whole file about 2-3 times. However, this is still just a constant cost. 

Another thing I missed now that I'm looking back at my code, was that I accidentally declared my struct's data members in the wrong order. Now each one has a lot more wasted space. I should have declared the strings first because those are 8 byte aligned... As of now, there's a good 22 bytes wasted per Rule object that I could have gotten rid of.

Finally, I know my algorithm isn't the optimal rule matching algorithm. So there's the biggest optimization that I could make. I just don't know how, but I will look into it after submitting this.

### MISC.
In total I spent 78 minutes in design and implementation. However, that does not include writing comments on my code and reading through everything again. Also, it doesn't include the more extensive test cases. I only tested it with the 5 basic ones given already. After the 78 minutes though, I did spend about 15 more minutes testing and I fixed a small bug (I used unsigned int instead of int and it underflowed and gave me a segmentation fault for array index out of bound) It was quickly caught though. Hopefully, the few minutes I went over testing it don't matter too much. I did manage to speed up the process significantly by copying and pasting a lot of my old code though. For example, the file parsing would have taken me 30 minutes to do from scratch but instead took me 5 because I just had a coding exercise from Jane Street that I also wrote a very similar parser for. The skeleton of the header file was also taken from one of my old homeworks. The function that took the longest was probably the compare() function in the Rule struct (I'd guess about 30 minutes).


### ORDER OF PREFERENCE FOR TEAMS
My order of preference for teams is Platform first, Policy, then Data. Mainly because this is all relatively new to me and I see the most familiarity in Platform.
