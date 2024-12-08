Title: crate push

Summary: dictionary_builder is where most of my changes took place. I seperated the function into two parts, one that processes if single_map is true, and one if it is false. First I iterate over the lines to count the number of lines. I iterate over the threads and fill a Vec<Strings> with the lines to be computed by that thread. All of those Vec<String>s are then held in order by the Vec<Vec<string>> Sections. I used a DashMap for the double and triple, and a DashSet for the token_list. I then loop through the number of threads. each section is processed. The previous is calculated based on which section we are currently on. If we are on the first section, then the prevs are both None. If we are on some later section processing then we but take the last line of the previous section, token_split it, and retreieve the last 2 tokens as the 2 prev values.

tech details: I used sender and reciever from the std::sync::mpsc library to send between my threads and the main thread. I used a DashMap for the double and triple, and a DashSet for the token_list.

testing: ran unit tests, manual testing with different files.

testing performance: ran unit tests, and checked that it was faster, and got faster with more threads.