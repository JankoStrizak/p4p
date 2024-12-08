Summary:
    There are 2 layers in the kernel.cu. 
    
    The first layer is conv_layer which takes the 100x100 matrix as input, uses the 10 neurons to dot product all of the 5x5 submatrixes with the filter and output 10 20x20 matrixes.

    The second layer is the output_layer which takes the 10 20x20 matrix from the conv_layer as input, treats it as a 4000x1 vector, and does dot product with the different weights resulting in a 10 output vector.

    Both of these layers are called in the cuda.rs in the compute function in two different launch commands.

Tech details:
    This implementation uses a GPU to speed up the calculation. 
    The conv_layer creates a block for each neuron, and each block contains 20x20 threads, one for each dot product of a 5x5 matrix from the input matrix, and the 5x5 filter. This way each thread is responsible for one operation. This layer also converts any negative values to zero before outputting it.
    The output_layer has a block for each neuron aswell, and has 10 threads per block .his way each thread only has to do 400 calculations.

Testing:
    I tested by running my code succesfully, and running the comapre.py function. 

Performance Testing:
    I played around with the number of threads to optimize the runtime. I tried spawning more threads in the output_layer but found limited improvement. I am not sure why my GPU implementation is slower than the CPU implementation. I believe there is room for improvement in the output_layer because one thread is still doing 400 operations. But I found that spawning more threads does not increase performance. Also, in the course material, the professor points to 32 threads being optimal for running on the hardware.

