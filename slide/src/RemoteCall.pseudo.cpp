process_handler->SnapShotAll();
SnapShotData<SnapShotCategory::OEP> data;
data.data = {
    0xff, 0xd0 // call rax
    0xcc,      // int3, we use int3 to notify our tracer the function is called
    0xc3,      // ret, dummy ... you also could use some "junk code" to obfuscate the behavior
}; // about 64 bytes
patch_oep(pid, oep_addr, data);
// call the function
call_oep(pid, oep_addr, stack_higher_base, args);

// You should restore all
ErrorCode res = process_handler->Restore();