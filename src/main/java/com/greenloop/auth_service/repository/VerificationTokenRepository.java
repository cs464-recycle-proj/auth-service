package com.greenloop.auth_service.repository;

import com.greenloop.auth_service.model.VerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;
import java.util.UUID;
import java.time.Instant;
import java.util.List;

@Repository
public interface VerificationTokenRepository extends JpaRepository<VerificationToken, UUID> {

    Optional<VerificationToken> findByToken(String token);
    Optional<VerificationToken> findByUserId(UUID userId);
    List<VerificationToken> findByExpiryDateBeforeAndIsUsedIsFalse(Instant now);
}
