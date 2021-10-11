package com.demo.utility.mapper;

import com.demo.dtos.AccountDto;
import com.demo.models.Status;
import com.demo.models.UserEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.OffsetDateTime;

import static java.time.ZoneOffset.UTC;

@RequiredArgsConstructor
@Component
public class UserMapper {

    private final PasswordEncoder passwordEncoder;

    public UserEntity mapInfoDtoToEntity(AccountDto accountDto) {
        String encodedPassword = passwordEncoder.encode(accountDto.getPassword());
        return UserEntity.builder()
                .name(accountDto.getName())
                .email(accountDto.getEmail().toLowerCase())
                .password(encodedPassword)
                .status(Status.UNVERIFIED)
                .score(accountDto.getScore())
                .linkNumber(accountDto.getLinkNumber())
                .createdTime(OffsetDateTime.now(UTC))
                .updatedTime(OffsetDateTime.now(UTC))
                .build();
    }

}
