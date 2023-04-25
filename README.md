# cycle.o

## 实验环境

```bash
#uname -a
Linux buildroot 6.2.0-rc3-gaed8040f4aca-dirty #41 SMP PREEMPT Mon Apr 17 16:06:26 CST 2023 aarch64 GNU/Linux

```

optee 软件环境：OP-TEE  v3.21，linux 6.

## 功能

利用多线程，对系统调用表、中断描述符表、页表读写控制位、MMU使能位、内核代码段、应用进程代码段、内核模块代码段度量

## 说明

需要重新编译内核，导出find_module等函数

# tee_agent.o

参考ftpm.ko的设计

platform_driver_register(&ftpm_tee_plat_driver)，

- 调用ftpm_plat_tee_probe(struct platform_device *pdev)
  - 调用ftpm_tee_probe(struct device *dev) 
  - 调用tee_client_open_context(NULL, ftpm_tee_match, NULL,NULL);
    - 调用ftpm_tee_match（）
  - 填充uuid，调用tee_client_open_session(pvt_data->ctx, &sess_arg, NULL);
  - 调用tee_shm_alloc_kernel_buf(pvt_data->ctx, 填充buf
  - 调用tpm_chip_alloc(dev, &ftpm_tee_tpm_ops);填充ftpm_tee_tpm_ops，里面有send等函数
  - 调用tpm_chip_register(pvt_data->chip); 返回负数
    - 调用ftpm_tee_tpm_op_send(struct tpm_chip *chip, u8 *buf, size_t len)
      - 填充tee_ioctl_invoke_arg transceive_args
      - 填充tee_param command_params[4]
      - 调用 tee_shm_get_va(shm, 0);从shm割内存
      - 调用tee_client_invoke_func(pvt_data->ctx, &transceive_args,command_params);
      - 再次调用tee_shm_get_va(shm, command_params[1].u.memref.shm_offs);应该没啥用
    - 调用ftpm_tee_tpm_op_status(struct tpm_chip *chip)
    - 调用ftpm_tee_tpm_op_recv(struct tpm_chip *chip, u8 *buf, size_t count)
    - 重复以上步骤
  - 报错ftpm-tee_yzc: probe of tpm@0 failed with error -14
- 结束ftpm_plat_tee_probe(struct platform_device *pdev)

driver_register(&ftpm_tee_driver.driver);

comtext session chip都链接了pvt_data