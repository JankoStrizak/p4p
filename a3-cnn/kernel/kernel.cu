// Very minimal skeleton for the kernel

#include <stdio.h>

#define INPUT_DIM 100
#define FILTER_DIM 5
#define CONV_OUT_DIM 20
#define NUM_NEURONS 10
#define OUT_NEURON_DIM 4000
#define OUT_LAYER_SIZE 10


extern "C" __global__ void conv_layer(
    double inputs[INPUT_DIM][INPUT_DIM],
    double filters[NUM_NEURONS][FILTER_DIM][FILTER_DIM],
    double outputs[NUM_NEURONS][CONV_OUT_DIM][CONV_OUT_DIM]
) {
    int index = blockIdx.x + threadIdx.x;
    
    for (int i = 0; i < FILTER_DIM; i++) {
        for (int j = 0; j < FILTER_DIM; j++) {
            //dot product
            outputs[blockIdx.x][threadIdx.x][threadIdx.y] += filters[blockIdx.x][i][j] * inputs[threadIdx.x * FILTER_DIM + i][threadIdx.y * FILTER_DIM + j];
        }
    }

    //relu stuff
    if (outputs[blockIdx.x][threadIdx.x][threadIdx.y] < 0.0) {
        outputs[blockIdx.x][threadIdx.x][threadIdx.y] = 0.0;
    }
}

extern "C" __global__ void output_layer(
    double inputs[OUT_NEURON_DIM],
    double weights[OUT_LAYER_SIZE][OUT_NEURON_DIM],
    double outputs[OUT_LAYER_SIZE]
) {
    int thread_num = threadIdx.x; //0-9
    for (int i = 0; i < 400*thread_num + 400; i++) {
        outputs[blockIdx.x] += inputs[i] * weights[blockIdx.x][i];
    }
}