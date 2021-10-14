package com.example.springjpaoracle.model;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;

import javax.persistence.*;

@Entity
@Table(name = "PHONE")
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@Getter
@Setter
@RequiredArgsConstructor
@Accessors(chain = true)
public class Phone
{
    @Id
    @Column
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private int id;

    @Column
    private String phoneNumber;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "relatedStudentId")
    private Student relatedStudent;

}
