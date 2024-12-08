Title: single_map push

Summary: dictionary_builder is where most of my changes took place. First I iterate over the lines to count the number of lines. I iterate over the threads and fill a Vec<Strings> with the lines to be computed by that thread. All of those Vec<String>s are then held in order by the Vec<Vec<string>> Sections. I used the std::sync::mpsc library to sedn adn receive the dbl,trp, and all_token_loist from the threads to the main thread. I then loop through all of the senders, since there is exactly one per thread. each section is processed. The previous is calculated based on which section we are currently on. If we are on the first section, then the prevs are both None. If we are on some later section processing then we but take the last line of the previous section, token_split it, and retreieve the last 2 tokens as the 2 prev values. Finally, I retrieve the objects from the threads and combine them to prodiuce the final dbl, trpl, and token_list.

tech details: I used sender and reciever from the std::sync::mpsc library to send between my threads and the main thread

testing: ran unit tests, manual testing with different files.

testing performance: ran unit tests, and checked that it was faster, and got faster with more threads.