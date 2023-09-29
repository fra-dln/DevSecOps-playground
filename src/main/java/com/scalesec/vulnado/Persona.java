package com.scalesec.vulnado;
/*CWE-697: Incorrect Comparison*/

public class Persona {
    private String nome;
    private String cognome;
    private Integer eta; 

    public Persona(String name, String surname, Integer age){
        this.nome = name;
        this.cognome = surname;
        this.eta = age;
    }

    /*GETTER */
    public String GetNome(){
        return nome;    
    }
    public String GetCognome(){
        return cognome;
    }
    public Integer GetDataNascita(){
        return eta;
    }

    /*SETTER */
    public void SetNome(String nome){
        this.nome = nome;
    }
    public void SetCognome(String cognome){
        this.cognome = cognome;
    }
    public void SetDataNascita(Integer eta){
        this.eta = eta;
    }

    public Integer BadCheckPerDuplicati(){
        Persona p1 = new Persona("Carlo", "Rossi", 35 );
        Persona p2 = new Persona("Mario", "Bianchi", 34);
        Integer uguali = 0;

        if(p1.nome==p2.nome && p1.cognome==p2.cognome){
            uguali++;
        }

        return uguali;
    }
}
