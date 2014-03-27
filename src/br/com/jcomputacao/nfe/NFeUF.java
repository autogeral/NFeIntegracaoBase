/*
 * Copyright (C) 2010  J. Computacao LTDA
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * If it is your itention to get support for a commercial version of this
 * application get in touch with J. Computacao LTDA at http://www.jcomputacao.com.br
 *
 * Este programa a software livre: voce pode redistribui-lo e/ou modifica-lo
 * sob os termos da Licenca Pulica Generica (GNU GPL) como publicado pela
 * Free Software Foundation, na versao 3 da licenca ou alguma versao superior.
 *
 * This programa e distribuido na esperanca que seja util,
 * mas SEM QUALQUER GARANTIA; sem sequer a garantia implicita
 * de COMERCIALIZACAO or APTIDAO PARA UMA FINALIDADE PARTICULAR.
 * Leia a GNU GPL para mais detalhes.
 *
 * Voce deveria receber uma copia da GNU GPL junto com este programa
 * se nao o recebeu leia em <http://www.gnu.org/licenses/>.
 *
 * Se for sua intencao obter suporte para uma versao comercial desta
 * aplicacao entre em contato com J. Computacao LTDA em http://www.jcomputacao.com.br
 *
 */
package br.com.jcomputacao.nfe;

/**
 *
 * @author Murilo
 */
public enum NFeUF {

    RONDONIA(11, "RO", "Rondonia"),
    ACRE(12, "AC", "Acre"),
    AMAZONAS( 13, "AM", "Amazonas"),
    ROMAIMA(14, "RO", "Roraima"),
    PARA(15, "PA", "Para"),
    AMAPA(16, "AM", "Amapa"),
    TOCANTINS(17, "TO", "Tocantins"),
    MARANHAO(21, "MA", "Maranhao"),
    PIAUI(22, "PI", "Piaua"),
    CEARA(23, "CE", "Ceara"),
    RIO_NORTE(24, "RN", "Rio Grande do Norte"),
    PARAIBA(25, "PB", "Paraaba"),
    PERNAMBUCO(26, "PE", "Pernambuco"),
    ALAGOAS(27, "AL", "Alagoas"),
    SERGIPE(28, "SE", "Sergipe"),
    BAHIA(29, "BA", "Bahia"),
    MINAS(31, "MG", "Minas Gerais"),
    ESPIRITO_SANTO(32, "ES", "Esparito Santo"),
    RIO_JANEIRO(33, "RJ", "Rio de Janeiro"),
    SAO_PAULO(35, "SP", "Sao Paulo"),
    PARANA(41, "PR", "Parana"),
    SANTA_CATARINA(42, "SC", "Santa Catarina"),
    RIO_SUL(43, "RS", "Rio Grande do Sul"),
    MATO_GROSSO_SUL(50, "MS", "Mato Grosso do Sul"),
    MATO_GROSSO(51, "MG", "Mato Grosso"),
    GOIAS(52, "GO", "Goias"),
    DISTRITO_FEDERAL(53, "DF", "Distrito Federal");

    int codigo;
    String sigla;
    String nome;

    NFeUF(int cod, String sgs, String nom) {
        this.codigo = cod;
        this.sigla = sgs;
        this.nome = nom;
    }

    public String getCodigo() {
        return Integer.toString(codigo);
    }

    public String getNome() {
        return nome;
    }

    public String getSigla() {
        return sigla;
    }

    public static NFeUF porSigla(String sigla) {
        for (NFeUF uf : NFeUF.values()) {
            if (uf.sigla.equalsIgnoreCase(sigla)) {
                return uf;
            }
        }
        return null;
    }
    
    public static NFeUF porCodigo(int codigo) {
        for (NFeUF uf : NFeUF.values()) {
            if (uf.codigo == codigo) {
                return uf;
            }
        }
        return null;
    }
}
