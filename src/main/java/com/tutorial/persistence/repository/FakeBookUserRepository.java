package com.tutorial.persistence.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tutorial.persistence.model.FakeBookUser;

@Repository
public interface FakeBookUserRepository extends JpaRepository<FakeBookUser, String> {

}
