// This is the skeleton for the CUDA implementation

use crate::cnn::*;
use rustacuda::function::BlockSize;
use rustacuda::function::GridSize;
use rustacuda::launch;
use rustacuda::memory::DeviceBox;
use rustacuda::prelude::*;
use std::error::Error;
use std::ffi::CString;

// Fields need to be ordered this way so the DeviceBoxes are
// dropped before the Context. Otherwise the drop will panic.

pub struct CudaContext {
    conv_layer: DeviceBox<ConvLayer>,
    output_layer: DeviceBox<OutputLayer>,
    module: Module,
    stream: Stream,
    _context: Context,
}

impl CudaContext {
    pub fn init(cnn: &Cnn) -> Result<Self, Box<dyn Error>> {
        rustacuda::init(CudaFlags::empty())?;

        let ptx = CString::new(include_str!("../kernel/kernel.ptx"))?;
        let calc_context = Context::create_and_push(
            ContextFlags::MAP_HOST | ContextFlags::SCHED_AUTO,
            Device::get_device(0)?
        );
        
        Ok(CudaContext {
            conv_layer: DeviceBox::new(&cnn.conv_layer).unwrap(),
            output_layer: DeviceBox::new(&cnn.output_layer).unwrap(),
            module: Module::load_from_string(&ptx)?,
            stream: Stream::new(StreamFlags::NON_BLOCKING, None)?,
            _context: calc_context?,
        })
    }

    pub fn compute(&mut self, input: &InputMatrix) -> Result<OutputVec, Box<dyn Error>> {
        let mut r = OutputVec([0.0; OUT_LAYER_SIZE]);

        let mut input_matrix = DeviceBox::new(input).unwrap();
        let mut layer1_output =
            DeviceBox::new(
                &[[[0.0; CONV_OUT_DIM]; CONV_OUT_DIM]; CONV_LAYER_SIZE]
            )?;
        let mut layer2_output =
            DeviceBox::new(
                &[[[0.0; CONV_OUT_DIM]; CONV_OUT_DIM]; CONV_LAYER_SIZE]
            )?;
        let mut layer3_output = DeviceBox::new(&OutputVec(
            [0.0; OUT_LAYER_SIZE],
        )).unwrap();

        let conv_num_blocks = GridSize::x(OUT_LAYER_SIZE as u32);
        let thread_2dmatrix = BlockSize::xy(CONV_OUT_DIM as u32, CONV_OUT_DIM as u32);
        


        unsafe {
            let module = &self.module;
            let stream = &self.stream;
            // let size: u32 = u32::try_from(CONV_OUT_DIM).unwrap();
            // let layer_size: u32 = u32::try_from(CONV_LAYER_SIZE).unwrap();

            let result = launch!(module.conv_layer<<<conv_num_blocks, thread_2dmatrix, 0, stream>>>(
                input_matrix.as_device_ptr(),
                self.conv_layer.as_device_ptr(),
                layer1_output.as_device_ptr()
            ));
            result?;
        }
        self.stream.synchronize()?;

        // unsafe {
        //     let module = &self.module;
        //     let stream = &self.stream;

        //     let result = launch!(module.neg_to_zero<<<conv_grid_size, conv_block_size, 0, stream>>>(
        //         layer1_output.as_device_ptr(),
        //         self.neg_to_zero.as_device_ptr(),
        //         layer2_output.as_device_ptr()
        //     ));
        //     result?;
        // }
        // self.stream.synchronize()?;

        let out_num_blocks = GridSize::x(OUT_LAYER_SIZE as u32);
        let thread_per_block = BlockSize::x(10 as u32);

        unsafe {
            let module = &self.module;
            let stream = &self.stream;
            // let size: u32 = u32::try_from(OUT_LAYER_SIZE).unwrap();

            let result = launch!(module.output_layer<<<out_num_blocks, thread_per_block, 0, stream>>>(
                layer1_output.as_device_ptr(),
                self.output_layer.as_device_ptr(),
                layer3_output.as_device_ptr()
            ));
            result?;
        }

        self.stream.synchronize()?;

        layer3_output.copy_to(&mut r);

        Ok(r)
        // Err("Not implemented")?
    }
}
