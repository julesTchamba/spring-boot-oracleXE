package com.example.springjpaoracle.model;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;

import javax.persistence.*;
import java.util.List;

@Entity
@Table(name = "STUDENT")
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@Getter
@Setter
@RequiredArgsConstructor
@Accessors(chain = true)
public class Student
{
    @Id
    @Column
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private int id;

    @Column(unique = true, nullable = false)
    @EqualsAndHashCode.Include
    private String keycloakId;

    @OneToMany(mappedBy = "relatedStudent")
    private List<Phone> phoneNumbers;

    @ManyToMany(cascade = CascadeType.REMOVE)
    @JoinTable(
            name = "STUDENT_COURSE_REGISTER",
            joinColumns = @JoinColumn(name = "STUDENT_ID", referencedColumnName = "ID"),
            inverseJoinColumns = @JoinColumn(name = "COURSE_ID", referencedColumnName = "ID")
    )
    private List<Course> courses;

    @OneToMany(mappedBy = "student")
    private List<StudentCourseScore> scores;

}
