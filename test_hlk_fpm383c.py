import time
from hlk_fpm383c import HLK_FPM383C, find_comm_ports


matched_ports = find_comm_ports(".*CH340.*")
if len(matched_ports) == 0:
    print("No device found")
    exit()
else:
    port = matched_ports[0][0]

device = HLK_FPM383C(port=port, password=b"\x00\x00\x00\x00")
device.init_comm()

# device.set_baudrate(57600)

# device.set_password(b"\x00\x00\x00\x00", write_to_flash=True)

# print(device.check_connection())
# print(device.get_fp_module_id())
print(device.get_stored_template_num())
# print(device.get_matching_threshold())
# print(device.get_gain())

# device.set_system_policy(rotation360=True)
# print(device.get_system_policy())

# device.set_led(mode="off", color="none")

# device.reset_fp_module()

# print(device.detect_finger_pressed())

print(device.report_stored_templates())
# print(device.check_finger_id_exists(0))
# print(device.check_finger_id_exists(1))

# device.cancel_registration_or_matching()

# press_idx = 1
# cur_progress = 0
# device.register_fingerprint_async(press_idx)
# while True:
#     time.sleep(0.5)
#     ret = device.check_registration_status()
#     if ret is None:
#         continue
#     if "progress" not in ret:
#         print("Registration failed")
#         break
#     if ret["finished"]:
#         print("Registration finished")
#         break
#     if ret["progress"] > cur_progress:
#         press_idx += 1
#         cur_progress = ret["progress"]
#         device.register_fingerprint_async(press_idx)

# device.save_fingerprint_template(4)
# time.sleep(0.5)
# print(device.check_template_saving_result())

# device.confirm_fingerprint_registration()
# print(device.check_registration_confirmation_result())

# print(device.auto_register_and_save(finger_id=0, num_press=6, need_lift=True))

# device.delete_fingerprint_template(4)
# time.sleep(0.5)
# print(device.check_template_deletion_result())
# print(device.report_stored_templates())

# device.delete_fingerprint_template_sync(finger_id=0)
# print(device.report_stored_templates())

# 执行命令的同时要按下手指；查看结果应该等待一段时间
# device.match_fingerprint_async()
# time.sleep(0.5)
# device.cancel_registration_or_matching()
# print(device.check_matching_result())

# print(device.match_fingerprint_sync())

# device.update_stored_feature(2)
# time.sleep(0.5)
# print(device.check_feature_updating_result())

# template_data = device.upload_template(0)
# with open("template_data.bin", "wb") as f:
#     f.write(template_data)

# with open("template_data.bin", "rb") as f:
#     template_data = f.read()
# device.download_template(2, template_data)

# device.set_finger_enroll_num(6)

device.close_comm()
