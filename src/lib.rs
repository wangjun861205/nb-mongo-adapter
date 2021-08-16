use async_trait::async_trait;
use casbin::{error::AdapterError, Adapter, Filter, Model, Result};
use futures::{future::ready, TryStreamExt};
use mongodb::bson::Document;
use mongodb::{bson::doc, error::Error, Client, Collection};
use serde::{Deserialize, Serialize};
use std::hash::Hash;
use std::{collections::hash_map::DefaultHasher, hash::Hasher};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    sec: String,
    ptype: String,
    rule: Vec<String>,
    digest: String,
}

impl Policy {
    pub fn new<I, T, S, P>(sec: S, ptype: P, rule: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
        S: Into<String>,
        P: Into<String>,
    {
        let mut hasher = DefaultHasher::new();
        let s = sec.into();
        let p = ptype.into();
        let r: Vec<String> = rule.into_iter().map(|v| v.into()).collect();
        s.clone().hash(&mut hasher);
        p.clone().hash(&mut hasher);
        r.clone().hash(&mut hasher);
        Self {
            sec: s,
            ptype: p,
            rule: r,
            digest: format!("{:x}", hasher.finish()),
        }
    }
}

#[derive(Debug, Clone)]
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
                          "unique": true,
                          "name": "digest_1",
                      },
                  ],
                },
                None,
            )
            .await
            .or_else(|e| {
                let Error { kind, .. } = e.clone();
                if let mongodb::error::ErrorKind::Command(mongodb::error::CommandError { code, .. }) = kind.as_ref() {
                    if code == &86 {
                        return Ok(doc! {});
                    }
                };
                Err(e)
            })?;
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
        let mut p_cond = doc! { "sec": "p" };
        f.p.iter().enumerate().for_each(|(i, &s)| {
            if s != "" {
                p_cond.insert(format!("rule.{}", i), s);
            }
        });
        self.coll
            .find(p_cond, None)
            .await
            .map_err(|e| AdapterError(Box::new(e)))?
            .map_err(|e| AdapterError(Box::new(e)))
            .try_for_each(|v| {
                m.add_policy("p", &v.ptype, v.rule);
                ready(Ok(()))
            })
            .await?;
        let mut g_cond = doc! { "sec": "g" };
        f.p.iter().enumerate().for_each(|(i, &s)| {
            if s != "" {
                g_cond.insert(format!("rule.{}", i), s);
            }
        });
        self.coll
            .find(g_cond, None)
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
            let mut q: Vec<Document> = rule
                .into_iter()
                .enumerate()
                .filter_map(|(i, v)| {
                    if v != "" {
                        return Some(doc! {format!("rule.{}", i): v});
                    }
                    None
                })
                .collect();
            q.push(doc! { "sec": sec });
            q.push(doc! { "ptype": ptype});
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

    const URI: &str = "mongodb://localhost:27017";
    const DB: &str = "casbin";
    const COLL: &str = "policy";

    #[tokio::test]
    async fn new_adapter() {
        let adapter = NBAdapter::new(URI, DB).await.unwrap();
    }

    #[tokio::test]
    async fn clear_policy() {
        let mut adapter = NBAdapter::new(URI, DB).await.unwrap();
        assert!(adapter.clear_policy().await.is_ok());
        let client = Client::with_uri_str(URI).await.unwrap();
        assert_eq!(client.database(DB).collection::<Document>(COLL).count_documents(doc! {}, None).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn add_policy() {
        let mut adapter = NBAdapter::new(URI, DB).await.unwrap();
        assert!(adapter.clear_policy().await.is_ok());
        assert!(adapter
            .add_policy("p", "p", vec!["user1", "resource1", "read", "allow"].into_iter().map(str::to_owned).collect())
            .await
            .is_ok());
        let client = Client::with_uri_str(URI).await.unwrap();
        let p = client
            .database(DB)
            .collection::<Policy>(COLL)
            .find_one(doc! {"sec": "p", "ptype": "p", "rule": vec!["user1", "resource1", "read", "allow"]}, None)
            .await
            .unwrap();
        assert_eq!(p, Some(Policy::new("p", "p", vec!["user1", "resource1", "read", "allow"])));
    }

    #[tokio::test]
    async fn add_policies() {
        let mut adapter = NBAdapter::new(URI, DB).await.unwrap();
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
    async fn load_policy() {
        let adapter = NBAdapter::new("mongodb://localhost:27017", "casbin").await.unwrap();
        let mut e = casbin::Enforcer::new("model.conf", adapter.clone()).await.unwrap();
        assert_eq!(e.clear_policy().await.is_ok(), true);
        assert_eq!(e.add_policy(vec!["user1", "res1", "read", "allow"].into_iter().map(str::to_owned).collect()).await.is_ok(), true);
        assert_eq!(e.add_policy(vec!["user1", "res1", "read", "deny"].into_iter().map(str::to_owned).collect()).await.is_ok(), true);
        let e1 = casbin::Enforcer::new("model.conf", adapter).await.unwrap();
        assert_eq!(e1.enforce(("user1", "res1", "read")).unwrap(), true);
        assert_eq!(e1.enforce(("user1", "res1", "write")).unwrap(), false);
    }

    #[tokio::test]
    async fn load_filtered_policy() {
        let adapter = NBAdapter::new("mongodb://localhost:27017", "casbin").await.unwrap();
        let mut e = casbin::Enforcer::new("model.conf", adapter.clone()).await.unwrap();
        e.clear_policy().await.unwrap();
        assert_eq!(e.add_policy(vec!["user1", "res1", "read", "allow"].into_iter().map(str::to_owned).collect()).await.is_ok(), true);
        assert_eq!(e.add_policy(vec!["user1", "res1", "read", "deny"].into_iter().map(str::to_owned).collect()).await.is_ok(), true);
        assert_eq!(e.add_policy(vec!["user2", "res2", "read", "allow"].into_iter().map(str::to_owned).collect()).await.is_ok(), true);
        assert_eq!(e.add_policy(vec!["user2", "res2", "read", "deny"].into_iter().map(str::to_owned).collect()).await.is_ok(), true);
        assert_eq!(
            e.load_filtered_policy(Filter {
                p: vec!["user1", "", "", ""],
                g: vec![],
            })
            .await
            .is_ok(),
            true
        );
        assert_eq!(e.enforce(("user1", "res1", "read")).unwrap(), true);
        assert_eq!(e.enforce(("user2", "res2", "read")).unwrap(), false);
        assert_eq!(
            e.load_filtered_policy(Filter {
                p: vec!["user2", "", "", ""],
                g: vec![],
            })
            .await
            .is_ok(),
            true
        );
        assert_eq!(e.enforce(("user1", "res1", "read")).unwrap(), false);
        assert_eq!(e.enforce(("user2", "res2", "read")).unwrap(), true);
    }
}
