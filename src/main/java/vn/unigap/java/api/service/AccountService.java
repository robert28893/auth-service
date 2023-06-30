package vn.unigap.java.api.service;

import vn.unigap.java.api.dto.in.ConfirmRegisterDtoIn;
import vn.unigap.java.api.dto.in.RegisterDtoIn;
import vn.unigap.java.api.dto.out.AccountDtoOut;

public interface AccountService {
	void register(RegisterDtoIn registerDtoIn);
	void confirmRegister(ConfirmRegisterDtoIn confirmRegisterDtoIn);
	AccountDtoOut getProfile();
}
