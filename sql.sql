CREATE TABLE IF NOT EXISTS users ( 
    `ID` int NOT NULL AUTO_INCREMENT, 
    `email` varchar(50) NOT NULL, 
    `username` varchar(50) NOT NULL, 
    `password` varchar(200) NOT NULL, 
    `verified` boolean, 
    `discordID` varchar(20), 
    
    PRIMARY KEY (`ID`) 
);