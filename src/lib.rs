use async_trait::async_trait;
use casbin::{error::AdapterError, Adapter, Filter, Model, Result};
use futures::{future::ready, TryStreamExt};
use mongodb::bson::Document;
use mongodb::{bson::doc, error::Error, Client, Collection, Cursor};
use serde::{Deserialize, Serialize};
use std::hash::Hash;
use std::sync::{Arc, Mutex};
use std::{collections::hash_map::DefaultHasher, hash::Hasher};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Policy {
    sec: String,
    ptype: String,
    rule: Vec<String>,
    digest: String,
}

impl Policy {
    pub fn new(sec: impl Into<String>, ptype: impl Into<String>, rule: Vec<String>) -> Self {
        let mut hasher = DefaultHasher::new();
        let s = sec.into();
        let p = ptype.into();
        s.clone().hash(&mut hasher);
        p.clone().hash(&mut hasher);
        rule.clone().hash(&mut hasher);
        Self {
            sec: s,
            ptype: p,
            rule,
            digest: format!("{:x}", hasher.finish()),
        }
    }
}

struct NBAdapter {
    coll: Collection<Policy>,
    is_filtered: bool,
}

impl NBAdapter {
    pub async fn new(uri: &str, db: &str) -> std::result::Result<Self, Error> {
        let client = Client::with_uri_str(uri).await?;
        let database = client.database(db);
        database
            .run_command(
                doc! {
                  "createIndexes": "policy",
                  "indexes": [
                      {
                          "key": {
                            "digest": 1
                          },
                          "name": "digest_1",
                      },
                  ],
                },
                None,
            )
            .await?;
        Ok(Self {
            coll: database.collection("policy"),
            is_filtered: false,
        })
    }
}

#[async_trait]
impl Adapter for NBAdapter {
    async fn load_policy(&self, m: &mut dyn Model) -> Result<()> {
        self.coll
            .find(doc! {}, None)
            .await
            .map_err(|e| AdapterError(Box::new(e)))?
            .map_err(|e| AdapterError(Box::new(e)))
            .try_for_each(|v| {
                m.add_policy(&v.sec, &v.ptype, v.rule);
                ready(Ok(()))
            })
            .await?;
        Ok(())
    }
    async fn load_filtered_policy<'a>(&mut self, m: &mut dyn Model, f: Filter<'a>) -> Result<()> {
        self.coll
            .find(
                doc! { "sec": "p", "rule": f.p.iter().filter_map(|v| {
                    if v == &"" {
                        None
                    } else {
                        Some(v.to_owned())
                    }
                }).collect::<Vec<&str>>()},
                None,
            )
            .await
            .map_err(|e| AdapterError(Box::new(e)))?
            .map_err(|e| AdapterError(Box::new(e)))
            .try_for_each(|v| {
                m.add_policy("p", &v.ptype, v.rule);
                ready(Ok(()))
            })
            .await?;
        self.coll
            .find(
                doc! {"sec": "g", "rule": f.g.iter().filter_map(|v| {
                    if v == &"" {
                        None
                    } else {
                        Some(v.to_owned())
                    }
                }).collect::<Vec<&str>>()},
                None,
            )
            .await
            .map_err(|e| AdapterError(Box::new(e)))?
            .map_err(|e| AdapterError(Box::new(e)))
            .try_for_each(|v| {
                m.add_policy("g", &v.ptype, v.rule);
                ready(Ok(()))
            })
            .await?;
        self.is_filtered = true;
        Ok(())
    }

    async fn save_policy(&mut self, m: &mut dyn Model) -> Result<()> {
        self.coll.delete_many(doc! {}, None).await.map_err(|e| AdapterError(Box::new(e)))?;
        let model = m.get_model();
        let ptypes = model.get("p").unwrap();
        for (typ, rules) in ptypes {
            for rule in rules.get_policy() {
                let policy = Policy::new("p", typ, rule.clone());
                self.coll.insert_one(policy, None).await.map_err(|e| AdapterError(Box::new(e)))?;
            }
        }
        if let Some(gtypes) = model.get("g") {
            for (typ, rules) in gtypes {
                for rule in rules.get_policy() {
                    let policy = Policy::new("g", typ, rule.clone());
                    self.coll.insert_one(policy, None).await.map_err(|e| AdapterError(Box::new(e)))?;
                }
            }
        }
        Ok(())
    }

    async fn clear_policy(&mut self) -> Result<()> {
        self.coll.delete_many(doc! {}, None).await.map_err(|e| AdapterError(Box::new(e)))?;
        Ok(())
    }

    fn is_filtered(&self) -> bool {
        self.is_filtered
    }
    async fn add_policy(&mut self, sec: &str, ptype: &str, rule: Vec<String>) -> Result<bool> {
        self.coll.insert_one(Policy::new(sec, ptype, rule), None).await.map_err(|e| AdapterError(Box::new(e)))?;
        Ok(true)
    }
    async fn add_policies(&mut self, sec: &str, ptype: &str, rules: Vec<Vec<String>>) -> Result<bool> {
        if rules.is_empty() {
            return Ok(false);
        }
        let policies: Vec<Policy> = rules.into_iter().map(|v| Policy::new(sec, ptype, v)).collect();
        self.coll.insert_many(policies, None).await.map_err(|e| AdapterError(Box::new(e)))?;
        Ok(true)
    }
    async fn remove_policy(&mut self, sec: &str, ptype: &str, rule: Vec<String>) -> Result<bool> {
        let res = self
            .coll
            .delete_one(doc! {"sec": sec, "ptype": ptype, "rule": rule}, None)
            .await
            .map_err(|e| AdapterError(Box::new(e)))?;
        Ok(res.deleted_count > 0)
    }
    async fn remove_policies(&mut self, sec: &str, ptype: &str, rules: Vec<Vec<String>>) -> Result<bool> {
        for rule in rules {
            let q: Vec<Document> = rule
                .into_iter()
                .enumerate()
                .filter_map(|(i, v)| {
                    if v != "" {
                        return Some(doc! {format!("rule.{}", i): v});
                    }
                    None
                })
                .collect();
            self.coll.delete_many(doc! { "$and": q}, None).await.map_err(|e| AdapterError(Box::new(e)))?;
        }
        Ok(true)
    }
    async fn remove_filtered_policy(&mut self, sec: &str, ptype: &str, field_index: usize, field_values: Vec<String>) -> Result<bool> {
        self.coll
            .delete_many(doc! { "sec": sec, "ptype": ptype, format!("rule.{}", field_index): format!("$in: {:?}", field_values)}, None)
            .await
            .map_err(|e| AdapterError(Box::new(e)))?;
        Ok(true)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use casbin::prelude::*;
    use mongodb::options::{CollectionOptions, SelectionCriteria};

    #[tokio::test]
    async fn test() {
        let adapter = NBAdapter::new("mongodb://localhost:27017", "casbin").await.unwrap();
        let mut e = casbin::Enforcer::new("model.conf", adapter).await.unwrap();
        println!("{}", e.enforce(("a", "b", "c")).unwrap());
        println!("{}", e.enforce(("d", "e", "f")).unwrap());
        println!("{}", e.enforce(("g", "h", "i")).unwrap());
        e.remove_policy(vec!["a".to_owned(), "b".to_owned(), "c".to_owned()]).await.unwrap();
        println!("{}", e.enforce(("a", "b", "c")).unwrap());
        // e.remove_filtered_policy(0, vec!["d".to_owned(), "e".to_owned(), "f".to_owned()]).await.unwrap();
        // println!("{}", e.enforce(("d", "e", "f")).unwrap());
        e.save_policy().await.unwrap();
    }

    #[tokio::test]
    async fn add_policy() {
        let adapter = NBAdapter::new("mongodb://localhost:27017", "casbin").await.unwrap();
        let mut e = casbin::Enforcer::new("model.conf", adapter).await.unwrap();
        e.clear_policy().await.unwrap();
        e.add_policy(vec!["a", "b", "c"].into_iter().map(str::to_owned).collect()).await.unwrap();
    }

    #[tokio::test]
    async fn add_role() {
        let adapter = NBAdapter::new("mongodb://localhost:27017", "casbin").await.unwrap();
        let mut e = casbin::Enforcer::new("model.conf", adapter).await.unwrap();
        e.clear_policy().await.unwrap();
        e.add_policy(vec!["user", "resource1", "read", "allow"].into_iter().map(str::to_owned).collect()).await.unwrap();
        e.add_policy(vec!["user", "resource1", "write", "deny"].into_iter().map(str::to_owned).collect()).await.unwrap();
        e.add_policy(vec!["admin", "resource1", "read", "allow"].into_iter().map(str::to_owned).collect()).await.unwrap();
        e.add_policy(vec!["admin", "resource1", "write", "allow"].into_iter().map(str::to_owned).collect()).await.unwrap();
        e.add_role_for_user("user1", "user", None).await.unwrap();
        e.add_role_for_user("admin1", "admin", None).await.unwrap();
        e.save_policy().await.unwrap();
        assert!(e.enforce(("user1", "resource1", "read")).unwrap() == true);
        assert!(e.enforce(("user1", "resource1", "write")).unwrap() == false);
        assert!(e.enforce(("admin1", "resource1", "read")).unwrap() == true);
        assert!(e.enforce(("admin1", "resource1", "write")).unwrap() == true);
    }

    #[tokio::test]
    async fn create_index() {
        let db = Client::with_uri_str("mongodb://localhost:27017").await.unwrap().database("casbin");
        db.run_command(
            doc! {
              "createIndexes": "policy",
              "indexes": [
                  {
                      "key": {
                        "digest": 1
                      },
                      "name": "digest_1",
                  },
              ],
            },
            None,
        )
        .await
        .unwrap();
    }

    use thiserror::Error as ThisError;

    #[derive(ThisError, Debug, Eq, PartialEq)]
    enum MyError {
        #[error("I hate 4")]
        FourError,
    }

    #[test]
    fn test_map_error() {
        let l = [1, 2, 3, 4, 5, 6];
        let res = l
            .iter()
            .map(|v| {
                if v == &4 {
                    return Err(MyError::FourError);
                }
                println!("{}", v);
                Ok(())
            })
            .collect::<std::result::Result<(), MyError>>();
        assert_eq!(res, Err(MyError::FourError))
    }
}
