package com.demo.repositories;

import com.demo.models.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
@EnableJpaRepositories
public interface UserRepository extends JpaRepository<UserEntity, Long> {

    @Query("select u from UserEntity as u where u.email = :email")
    Optional<UserEntity> findByEmail(@Param("email") String email);

    @Query("select u from UserEntity u where u.email = :email and u.status <> 'CANCELLED'")
    Optional<UserEntity> findUserEntityByEmail(@Param("email") String email);

    @Query("select u from UserEntity as u where u.email = :email and u.status = 'UNVERIFIED'")
    Optional<UserEntity> findUnverifiedStatusByEmail(@Param("email") String email);

    @Query("select u from UserEntity as u where u.id = :id and u.status <> 'CANCELLED'")
    Optional<UserEntity> findUserEntityById(@Param("id") Long id);

    @Modifying
    @Query("update UserEntity u set u.status = :status where u.email = :email")
    int updateStatusByEmail(@Param("email") String email, @Param("status") Enum status);

    Optional<List<UserEntity>> findByIdIn(List<Long> id);

    boolean existsById(Long id);
}
