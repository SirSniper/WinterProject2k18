CREATE DATABASE IF NOT EXISTS Chat;
USE Chat;
SET SQL_SAFE_UPDATES = 0;
CREATE TABLE IF NOT EXISTS Users (
    userid VARCHAR(64) not null,
    username VARCHAR(64) not null,
    email VARCHAR(64) not null,
    passwordhash VARCHAR(128) not null,
    salt VARCHAR(16) not null, 
    PRIMARY KEY(userid));

CREATE TABLE IF NOT EXISTS Tokens (
    userid VARCHAR(64) not null,
    token VARCHAR(32) not null,
    spawnTime DATETIME not null, 
    PRIMARY KEY(userid, token), 
    FOREIGN KEY(userid) REFERENCES Users (userid));

CREATE TABLE IF NOT EXISTS Groups (
    groupid VARCHAR(64) not null,
    groupname VARCHAR(128) not null,
    PRIMARY KEY(groupid));

CREATE TABLE IF NOT EXISTS GroupMembers (
    groupid VARCHAR(64) not null,
    userid VARCHAR(64) not null,
    PRIMARY KEY(groupid, userid),
    FOREIGN KEY (groupid) REFERENCES Groups(groupid),
    FOREIGN KEY (userid) REFERENCES Users(userid));